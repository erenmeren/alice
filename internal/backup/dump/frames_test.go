package dump_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/backup/dump"
)

type frame struct {
	kind dump.Kind
	name string
	data []byte
}

// encode writes frames with the package encoder.
func encode(t testing.TB, frames ...frame) []byte {
	t.Helper()
	var b bytes.Buffer
	enc := dump.NewEncoder(&b)
	for _, f := range frames {
		require.NoError(t, enc.Frame(f.kind, f.name, f.data))
	}
	require.NoError(t, enc.Flush())
	return b.Bytes()
}

// raw builds one frame by hand, so the tests can make frames the encoder refuses.
func raw(kind byte, name []byte, dataLen uint32, data []byte) []byte {
	b := []byte{kind}
	b = binary.BigEndian.AppendUint16(b, uint16(len(name)))
	b = append(b, name...)
	b = binary.BigEndian.AppendUint32(b, dataLen)
	return append(b, data...)
}

func decodeAll(t testing.TB, b []byte) ([]dump.Frame, error) {
	t.Helper()
	dec := dump.NewDecoder(bytes.NewReader(b))
	var out []dump.Frame
	for {
		f, err := dec.Next()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		out = append(out, f)
	}
}

var (
	manifest = frame{dump.Manifest, "manifest.json", []byte(`{}`)}
	seqs     = frame{dump.Sequences, "sequences.json", []byte(`{}`)}
	end      = frame{dump.End, "end", []byte(`{"tables":1,"files":1}`)}
)

func TestFramesRoundTrip(t *testing.T) {
	big := bytes.Repeat([]byte{0xA5}, dump.MaxData)
	longName := strings.Repeat("ş", 127) + "x" // 255 bytes of UTF-8
	require.Len(t, longName, dump.MaxName)
	in := []frame{
		manifest,
		{dump.TableStart, longName, []byte(`{"name":"t"}`)},
		{dump.Data, longName, nil},
		{dump.Data, longName, big},
		{dump.TableEnd, longName, []byte(`{"rows":0}`)},
		{dump.TableStart, "users", nil},
		{dump.TableEnd, "users", nil},
		seqs,
		{dump.File, "keys/master.key", []byte("k")},
		{dump.File, "state/hwm.dat", nil},
		end,
	}
	got, err := decodeAll(t, encode(t, in...))
	require.NoError(t, err)
	require.Len(t, got, len(in))
	for i, f := range in {
		assert.Equal(t, f.kind, got[i].Kind, i)
		assert.Equal(t, f.name, got[i].Name, i)
		assert.Equal(t, len(f.data), len(got[i].Data), i)
		assert.True(t, bytes.Equal(f.data, got[i].Data), i)
	}
}

func TestJSONFrame(t *testing.T) {
	var b bytes.Buffer
	enc := dump.NewEncoder(&b)
	require.NoError(t, enc.JSON(dump.Manifest, "manifest.json", map[string]int{"a": 1}))
	require.Error(t, enc.JSON(dump.Manifest, "manifest.json", func() {}), "a value JSON cannot encode")
	require.NoError(t, enc.Flush())
	dec := dump.NewDecoder(&b)
	f, err := dec.Next()
	require.NoError(t, err)
	assert.JSONEq(t, `{"a":1}`, string(f.Data))
}

func TestEncoderRefusesBadFrames(t *testing.T) {
	enc := dump.NewEncoder(io.Discard)
	assert.ErrorIs(t, enc.Frame('X', "x", nil), dump.ErrPayload)
	assert.ErrorIs(t, enc.Frame(dump.Data, strings.Repeat("a", 256), nil), dump.ErrPayload)
	assert.ErrorIs(t, enc.Frame(dump.Data, "\xff", nil), dump.ErrPayload)
	assert.ErrorIs(t, enc.Frame(dump.Data, "t", make([]byte, dump.MaxData+1)), dump.ErrPayload)
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestEncoderReportsWriteErrors(t *testing.T) {
	enc := dump.NewEncoder(failWriter{})
	err := enc.Frame(dump.Data, "t", make([]byte, 128<<10)) // larger than the buffer
	if err == nil {
		err = enc.Flush()
	}
	require.Error(t, err)
	assert.Error(t, enc.Flush(), "the error is sticky")
}

func TestDecoderRefuses(t *testing.T) {
	m := encode(t, manifest)
	tStart := encode(t, frame{dump.TableStart, "users", nil})
	cases := []struct {
		name   string
		stream []byte
	}{
		{"unknown kind", append(bytes.Clone(m), raw('X', []byte("x"), 0, nil)...)},
		{"name of 256 bytes", append(bytes.Clone(m), raw('T', bytes.Repeat([]byte("a"), 256), 0, nil)...)},
		{"data length 1 MiB + 1", append(bytes.Clone(m), raw('T', []byte("a"), dump.MaxData+1, nil)...)},
		{"truncated length field", append(bytes.Clone(m), raw('T', []byte("a"), 0, nil)[:5]...)},
		{"truncated name", append(bytes.Clone(m), raw('T', []byte("abc"), 0, nil)[:4]...)},
		{"truncated kind only", append(bytes.Clone(m), 'T')},
		{"truncated data", append(bytes.Clone(m), raw('T', []byte("a"), 10, []byte("12345"))...)},
		{"invalid UTF-8 name", append(bytes.Clone(m), raw('T', []byte{0xff, 0xfe}, 0, nil)...)},
		{"empty stream", nil},
		{"first frame is not the manifest", encode(t, frame{dump.TableStart, "users", nil})},
		{"D before any T", encode(t, manifest, frame{dump.Data, "users", nil})},
		{"E before any T", encode(t, manifest, frame{dump.TableEnd, "users", nil})},
		{"E whose name differs", encode(t, manifest, frame{dump.TableStart, "users", nil}, frame{dump.TableEnd, "sessions", nil})},
		{"T inside an open table", encode(t, manifest, frame{dump.TableStart, "a", nil}, frame{dump.TableStart, "b", nil})},
		{"Q inside an open table", append(append(bytes.Clone(m), tStart...), encode(t, seqs)...)},
		{"repeated table", encode(t, manifest, frame{dump.TableStart, "a", nil}, frame{dump.TableEnd, "a", nil},
			frame{dump.TableStart, "a", nil})},
		{"second M", encode(t, manifest, manifest)},
		{"F before Q", encode(t, manifest, frame{dump.File, "keys/master.key", nil})},
		{"Z before Q", encode(t, manifest, end)},
		{"T after Q", encode(t, manifest, seqs, frame{dump.TableStart, "a", nil})},
		{"second Q", encode(t, manifest, seqs, seqs)},
		{"anything after Z", append(encode(t, manifest, seqs, end), 0)},
		{"a frame after Z", encode(t, manifest, seqs, end, end)},
		{"ends before Z", encode(t, manifest, seqs)},
		{"ends inside a table", encode(t, manifest, frame{dump.TableStart, "a", nil})},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := decodeAll(t, c.stream)
			require.ErrorIs(t, err, dump.ErrPayload)
		})
	}
}

func TestDecoderErrorsAreSticky(t *testing.T) {
	dec := dump.NewDecoder(bytes.NewReader(encode(t, manifest, manifest, seqs, end)))
	_, err := dec.Next()
	require.NoError(t, err)
	for range 3 {
		_, err = dec.Next()
		require.ErrorIs(t, err, dump.ErrPayload)
	}
}

func TestDecoderAfterZ(t *testing.T) {
	dec := dump.NewDecoder(bytes.NewReader(encode(t, manifest, seqs, end)))
	for range 3 {
		_, err := dec.Next()
		require.NoError(t, err)
	}
	for range 2 {
		_, err := dec.Next()
		require.ErrorIs(t, err, io.EOF)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("disk read failed") }

func TestDecoderPassesReadErrors(t *testing.T) {
	dec := dump.NewDecoder(io.MultiReader(bytes.NewReader(encode(t, manifest)), errReader{}))
	_, err := dec.Next()
	require.NoError(t, err)
	_, err = dec.Next()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "disk read failed")
}
