package httpcheck

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// deadlineReader returns its text, then a clean end only after the context's deadline passed: the transport's answer
// when the deadline closes the connection under the body read (seen on CI with a slow-loris server).
type deadlineReader struct {
	ctx  context.Context
	text io.Reader
}

func (r deadlineReader) Read(p []byte) (int, error) {
	n, err := r.text.Read(p)
	if errors.Is(err, io.EOF) {
		<-r.ctx.Done()
	}
	return n, err
}

// Final review minor (R65): a body that ends cleanly only after the deadline is a timeout, never a pass; a body that
// ends before it reads on; a read error is classified.
func TestReadBody(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	assert.Equal(t, ReasonTimeout, readBody(ctx, deadlineReader{ctx: ctx, text: strings.NewReader("partial")}))

	live, stop := context.WithCancel(context.Background())
	defer stop()
	assert.Empty(t, readBody(live, strings.NewReader("ok\n")))
	assert.Equal(t, ReasonProtocol, readBody(live, io.MultiReader(strings.NewReader("x"), errReader{})))
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("connection reset") }
