package pcsc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSelectionRules(t *testing.T) {
	yk := "Yubico YubiKey OTP+FIDO+CCID 00 00"
	yk2 := "Yubico YubiKey OTP+FIDO+CCID 01 00"
	other := "Generic Smart Card Reader 00 00"

	for _, tc := range []struct {
		name    string
		readers []string
		want    string
		got     string
		err     error
		mention []string
	}{
		{name: "exact name wins over the yubikey", readers: []string{yk, other}, want: other, got: other},
		{name: "exact name of a yubikey among two", readers: []string{yk, yk2}, want: yk2, got: yk2},
		{name: "exact name is case-sensitive", readers: []string{yk}, want: "yubico yubikey otp+fido+ccid 00 00",
			err: ErrReaderNotFound, mention: []string{yk}},
		{name: "named reader missing", readers: []string{other}, want: yk, err: ErrReaderNotFound, mention: []string{other}},
		{name: "one yubikey wins", readers: []string{other, yk}, got: yk},
		{name: "matching is case-insensitive", readers: []string{other, "acme YUBIkey 00"}, got: "acme YUBIkey 00"},
		{name: "two yubikeys are ambiguous", readers: []string{yk, other, yk2}, err: ErrAmbiguousReader, mention: []string{yk, yk2}},
		{name: "no yubikey lists the readers present", readers: []string{other}, err: ErrReaderNotFound, mention: []string{other}},
		{name: "no reader at all", readers: nil, err: ErrNoReaders, mention: []string{"no smart card reader is connected", "Smart Card service"}},
		{name: "empty list", readers: []string{}, err: ErrNoReaders},
		{name: "named reader with no reader at all", readers: []string{}, want: yk, err: ErrNoReaders},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := pick(tc.readers, tc.want)
			if tc.err == nil {
				require.NoError(t, err)
				assert.Equal(t, tc.got, got)
				return
			}
			require.ErrorIs(t, err, tc.err)
			assert.Empty(t, got)
			for _, m := range tc.mention {
				assert.Contains(t, err.Error(), m)
			}
		})
	}
}

func TestAmbiguousSelectionDoesNotListOtherReaders(t *testing.T) {
	_, err := pick([]string{"YubiKey A", "Secret Corp Reader", "YubiKey B"}, "")
	require.ErrorIs(t, err, ErrAmbiguousReader)
	assert.NotContains(t, err.Error(), "Secret Corp Reader")
}

func TestReaderNamesAreQuotedInErrors(t *testing.T) {
	_, err := pick([]string{"evil\x1b[2Jreader"}, "")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "\x1b", "a reader name must not drive the terminal")
}

// fakeRaw is a card handle whose Transmit can be held until the test releases it, like a
// YubiKey waiting for a touch.
type fakeRaw struct {
	hold     chan struct{} // nil: answer at once
	started  chan struct{}
	resp     []byte
	err      error
	mu       sync.Mutex
	seen     [][]byte // the buffers Transmit received (not copies)
	seenData [][]byte // copies of what they held at the time
	discs    int
	disc     chan struct{}
	discErr  error
}

func newFakeRaw() *fakeRaw {
	return &fakeRaw{started: make(chan struct{}, 16), disc: make(chan struct{}, 16), resp: []byte{0x90, 0x00}}
}

func (f *fakeRaw) Transmit(apdu []byte) ([]byte, error) {
	f.mu.Lock()
	f.seen = append(f.seen, apdu)
	f.seenData = append(f.seenData, bytes.Clone(apdu))
	f.mu.Unlock()
	f.started <- struct{}{}
	if f.hold != nil {
		<-f.hold
	}
	return f.resp, f.err
}

func (f *fakeRaw) Disconnect() error {
	f.mu.Lock()
	f.discs++
	f.mu.Unlock()
	f.disc <- struct{}{}
	return f.discErr
}

func (f *fakeRaw) disconnects() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.discs
}

func identity(_ string, err error) error { return err }

func TestTransmitPassesTheResponseThrough(t *testing.T) {
	raw := newFakeRaw()
	c := newConn(raw, nil, identity)
	rsp, err := c.Transmit(context.Background(), []byte{0x00, 0xA4, 0x04, 0x00})
	require.NoError(t, err)
	assert.Equal(t, []byte{0x90, 0x00}, rsp)
	assert.Equal(t, [][]byte{{0x00, 0xA4, 0x04, 0x00}}, raw.seenData)
	require.NoError(t, c.Close())
	assert.Equal(t, 1, raw.disconnects())
}

func TestTransmitMapsErrors(t *testing.T) {
	raw := newFakeRaw()
	raw.err = errors.New("raw failure")
	c := newConn(raw, nil, func(string, error) error { return ErrCardRemoved })
	_, err := c.Transmit(context.Background(), []byte{0x00})
	require.ErrorIs(t, err, ErrCardRemoved)
	require.NoError(t, c.Close())
}

func TestTransmitRefusesAnEmptyCommand(t *testing.T) {
	raw := newFakeRaw()
	c := newConn(raw, nil, identity)
	_, err := c.Transmit(context.Background(), nil)
	require.Error(t, err)
	assert.Empty(t, raw.seen, "scard indexes cmd[0]: an empty command must never reach it")
	require.NoError(t, c.Close())
}

func TestTransmitWithADoneContextSendsNothing(t *testing.T) {
	raw := newFakeRaw()
	c := newConn(raw, nil, identity)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.Transmit(ctx, []byte{0x00})
	require.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, raw.seen)
	require.NoError(t, c.Close())
}

// The card's buffer is the connection's own copy, zeroed once the card answers: the caller may
// zero its PIN buffer as soon as Transmit returns, even after a cancel, without racing the
// goroutine still talking to the card.
func TestTransmitWorksOnACopyAndZeroesIt(t *testing.T) {
	raw := newFakeRaw()
	c := newConn(raw, nil, identity)
	apdu := []byte{0x00, 0x20, 0x00, 0x81, 0x06, '1', '2', '3', '4', '5', '6'}
	_, err := c.Transmit(context.Background(), apdu)
	require.NoError(t, err)
	require.Len(t, raw.seen, 1)
	assert.NotSame(t, &apdu[0], &raw.seen[0][0], "the card must get a copy")
	assert.Equal(t, apdu, raw.seenData[0])
	assert.Equal(t, make([]byte, len(apdu)), raw.seen[0], "the copy is zeroed after the card answered")
	require.NoError(t, c.Close())
}

func TestCancelWhileWaitingForTouchReturnsPromptly(t *testing.T) {
	raw := newFakeRaw()
	raw.hold = make(chan struct{})
	cancelled := make(chan struct{}, 1)
	c := newConn(raw, func() { cancelled <- struct{}{} }, identity)
	c.closeWait = 50 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := c.Transmit(ctx, []byte{0x00, 0x2A, 0x9E, 0x9A})
		done <- err
	}()
	<-raw.started
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
		require.ErrorIs(t, err, ErrAbandoned)
	case <-time.After(2 * time.Second):
		t.Fatal("Transmit did not return after cancel")
	}
	select {
	case <-cancelled:
	default:
		t.Error("cancel did not call the PC/SC context cancel")
	}

	// The connection is now unusable: nothing more reaches the card.
	_, err := c.Transmit(context.Background(), []byte{0x00})
	require.ErrorIs(t, err, ErrAbandoned)
	assert.Len(t, raw.seen, 1)

	// Close cannot release the handle while the card still holds the command (PC/SC serialises
	// calls on one context): it waits a bounded time and says so.
	err = c.Close()
	require.ErrorIs(t, err, ErrCloseTimeout)
	assert.Equal(t, 0, raw.disconnects())

	// The card answers (touch timeout): the goroutine releases the handle itself and ends.
	close(raw.hold)
	select {
	case <-raw.disc:
	case <-time.After(2 * time.Second):
		t.Fatal("the handle was not released after the card answered")
	}
	require.NoError(t, c.Close(), "Close after the release reports success")
	assert.Equal(t, 1, raw.disconnects())
}

func TestCancelThenCardAnswersReleasesWithoutClose(t *testing.T) {
	raw := newFakeRaw()
	raw.hold = make(chan struct{})
	c := newConn(raw, nil, identity)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := c.Transmit(ctx, []byte{0x00})
		done <- err
	}()
	<-raw.started
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
	close(raw.hold)
	select {
	case <-raw.disc:
	case <-time.After(2 * time.Second):
		t.Fatal("an abandoned connection must be released once the card answers")
	}
	require.NoError(t, c.Close())
	assert.Equal(t, 1, raw.disconnects())
}

func TestCloseWaitsForAnInFlightTransmit(t *testing.T) {
	raw := newFakeRaw()
	raw.hold = make(chan struct{})
	c := newConn(raw, nil, identity)
	done := make(chan error, 1)
	go func() {
		_, err := c.Transmit(context.Background(), []byte{0x00})
		done <- err
	}()
	<-raw.started
	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()
	time.Sleep(20 * time.Millisecond)
	assert.Equal(t, 0, raw.disconnects(), "no disconnect while the card holds the command")
	close(raw.hold)
	require.NoError(t, <-done)
	require.NoError(t, <-closed)
	assert.Equal(t, 1, raw.disconnects())
}

func TestCloseIsIdempotentAndSafeConcurrently(t *testing.T) {
	raw := newFakeRaw()
	c := newConn(raw, nil, identity)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() { assert.NoError(t, c.Close()) })
	}
	wg.Wait()
	require.NoError(t, c.Close())
	assert.Equal(t, 1, raw.disconnects())
	_, err := c.Transmit(context.Background(), []byte{0x00})
	require.ErrorIs(t, err, ErrClosed)
}

func TestConcurrentTransmitIsRefused(t *testing.T) {
	raw := newFakeRaw()
	raw.hold = make(chan struct{})
	c := newConn(raw, nil, identity)
	done := make(chan error, 1)
	go func() {
		_, err := c.Transmit(context.Background(), []byte{0x00})
		done <- err
	}()
	<-raw.started
	_, err := c.Transmit(context.Background(), []byte{0x01})
	require.ErrorIs(t, err, ErrBusy)
	close(raw.hold)
	require.NoError(t, <-done)
	require.NoError(t, c.Close())
}

// Close reports a failed release under its own operation, not as a transmit failure.
func TestDisconnectErrorsAreLabelledDisconnect(t *testing.T) {
	raw := newFakeRaw()
	raw.discErr = errors.New("raw disconnect failure")
	var ops []string
	c := newConn(raw, nil, func(op string, err error) error {
		ops = append(ops, op)
		return fmt.Errorf("%s: %w", op, err)
	})
	_, err := c.Transmit(context.Background(), []byte{0x00})
	require.NoError(t, err)
	err = c.Close()
	require.ErrorIs(t, err, raw.discErr)
	assert.Equal(t, []string{"disconnect"}, ops)
}

// waitIdle waits until the transmit goroutine has finished (the card answered and the connection
// is free again).
func waitIdle(t *testing.T, c *conn) {
	t.Helper()
	require.Eventually(t, func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return !c.busy
	}, 2*time.Second, time.Millisecond)
}

// The card answers in the instant between the last look at its answer and the abandon: the
// goroutine finished without releasing (it saw no abandon), so the cancel path releases the handle
// itself instead of holding it until Close.
func TestCancelRacingTheAnswerStillReleasesTheHandle(t *testing.T) {
	raw := newFakeRaw()
	raw.hold = make(chan struct{})
	cancels := 0
	c := newConn(raw, func() { cancels++ }, identity)
	c.abandonHook = func() {
		close(raw.hold)
		waitIdle(t, c)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := c.Transmit(ctx, []byte{0x00})
		done <- err
	}()
	<-raw.started
	cancel()
	require.ErrorIs(t, <-done, ErrAbandoned)
	assert.Equal(t, 1, raw.disconnects(), "released without Close")
	assert.Equal(t, 1, cancels, "the context was still live: cancel was called")
	require.NoError(t, c.Close())
	assert.Equal(t, 1, raw.disconnects())
}

// When the release has already started (here: Close after the card answered), the cancel path
// must not call the PC/SC cancel on a context that may be gone.
func TestCancelAfterReleaseDoesNotTouchTheContext(t *testing.T) {
	raw := newFakeRaw()
	raw.hold = make(chan struct{})
	cancels := 0
	c := newConn(raw, func() { cancels++ }, identity)
	c.abandonHook = func() {
		close(raw.hold)
		waitIdle(t, c)
		assert.NoError(t, c.Close())
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := c.Transmit(ctx, []byte{0x00})
		done <- err
	}()
	<-raw.started
	cancel()
	require.ErrorIs(t, <-done, ErrAbandoned)
	assert.Equal(t, 0, cancels, "no cancel on a released context")
	assert.Equal(t, 1, raw.disconnects())
}
