// Package dump is the backup payload (C7): a stream of length-prefixed frames, and the consistent logical dump of
// every ordinary table of the public schema with binary COPY inside one REPEATABLE READ snapshot, and its load.
//
// The package knows no other Alice module: it reads the catalog, copies rows and frames bytes.
package dump

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// Kind is the first byte of a frame.
type Kind byte

// The frame kinds of C7.
const (
	Manifest   Kind = 'M'
	TableStart Kind = 'T'
	Data       Kind = 'D'
	TableEnd   Kind = 'E'
	Sequences  Kind = 'Q'
	File       Kind = 'F'
	End        Kind = 'Z'
)

// Bounds of one frame.
const (
	MaxName = 255
	MaxData = 1 << 20
)

// maxTables bounds the number of table frames one stream may carry, so the set of seen names stays small.
const maxTables = 4096

const bufferSize = 64 << 10

// ErrPayload means the frame stream is malformed: a bad frame, a frame out of the order of C7, or a stream that ends
// before its end frame.
var ErrPayload = errors.New("dump: the backup payload is malformed")

// Frame is one decoded frame. Data belongs to the caller.
type Frame struct {
	Kind Kind
	Name string
	Data []byte
}

func validKind(k Kind) bool {
	switch k {
	case Manifest, TableStart, Data, TableEnd, Sequences, File, End:
		return true
	}
	return false
}

// Encoder writes frames. It buffers 64 KiB; call Flush at the end. The first write error is kept and returned by
// every later call.
type Encoder struct {
	w   *bufio.Writer
	err error
}

// NewEncoder returns an encoder that writes to w.
func NewEncoder(w io.Writer) *Encoder { return &Encoder{w: bufio.NewWriterSize(w, bufferSize)} }

// Frame writes one frame. It refuses (ErrPayload) an unknown kind, a name that is not UTF-8 or longer than MaxName, and
// data longer than MaxData. It does not check the order of the frames.
func (e *Encoder) Frame(kind Kind, name string, data []byte) error {
	if e.err != nil {
		return e.err
	}
	if !validKind(kind) || len(name) > MaxName || !utf8.ValidString(name) || len(data) > MaxData {
		return fmt.Errorf("%w: frame %q refused by the encoder", ErrPayload, kind)
	}
	var head [1 + 2]byte
	head[0] = byte(kind)
	binary.BigEndian.PutUint16(head[1:], uint16(len(name))) //nolint:gosec // G115: len(name) <= MaxName was checked
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(data))) //nolint:gosec // G115: len(data) <= MaxData was checked
	for _, b := range [][]byte{head[:], []byte(name), size[:], data} {
		if _, err := e.w.Write(b); err != nil {
			e.err = fmt.Errorf("dump: write the payload: %w", err)
			return e.err
		}
	}
	return nil
}

// JSON marshals v and writes it as one frame.
func (e *Encoder) JSON(kind Kind, name string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("dump: encode frame %q: %w", kind, err)
	}
	return e.Frame(kind, name, b)
}

// Flush writes the buffered frames.
func (e *Encoder) Flush() error {
	if e.err != nil {
		return e.err
	}
	if err := e.w.Flush(); err != nil {
		e.err = fmt.Errorf("dump: write the payload: %w", err)
	}
	return e.err
}

// decoder states: what may come next.
type state int

const (
	wantManifest   state = iota // nothing read yet: only M
	betweenTables               // after M or E: T or Q
	inTable                     // after T or D: D or E of the open table
	afterSequences              // after Q or F: F or Z
	done                        // after Z: nothing
)

// Decoder reads frames and enforces the order of C7: M, then T D* E per table, Q, F*, Z. It checks the kind, the name
// and the data length before it reads the data, so it never allocates more than MaxData for one frame. A repeated
// table name is refused here; the ascending order and the table set are checked by Load against the target. After Z,
// Next returns io.EOF at the end of the input and ErrPayload when anything follows. Every error is sticky.
type Decoder struct {
	r      *bufio.Reader
	state  state
	table  string
	tables map[string]bool
	err    error
}

// NewDecoder returns a decoder that reads from r.
func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{r: bufio.NewReaderSize(r, bufferSize), tables: map[string]bool{}}
}

func (d *Decoder) fail(format string, args ...any) error {
	d.err = fmt.Errorf("%w: "+format, append([]any{ErrPayload}, args...)...)
	return d.err
}

// readFull reads exactly len(b) bytes; an early end of the input is a malformed payload, any other error is kept.
func (d *Decoder) readFull(b []byte, what string) error {
	if _, err := io.ReadFull(d.r, b); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return d.fail("the payload ends inside the %s of a frame", what)
		}
		d.err = fmt.Errorf("dump: read the payload: %w", err)
		return d.err
	}
	return nil
}

// Next returns the next frame.
func (d *Decoder) Next() (Frame, error) {
	if d.err != nil {
		return Frame{}, d.err
	}
	kb, err := d.r.ReadByte()
	if err != nil {
		if !errors.Is(err, io.EOF) {
			d.err = fmt.Errorf("dump: read the payload: %w", err)
			return Frame{}, d.err
		}
		if d.state == done {
			d.err = io.EOF
			return Frame{}, io.EOF
		}
		return Frame{}, d.fail("the payload ends before its end frame")
	}
	if d.state == done {
		return Frame{}, d.fail("data after the end frame")
	}
	kind := Kind(kb)
	if !validKind(kind) {
		return Frame{}, d.fail("unknown frame kind 0x%02x", kb)
	}
	var n2 [2]byte
	if err := d.readFull(n2[:], "name length"); err != nil {
		return Frame{}, err
	}
	nameLen := int(binary.BigEndian.Uint16(n2[:]))
	if nameLen > MaxName {
		return Frame{}, d.fail("frame name of %d bytes", nameLen)
	}
	nameBytes := make([]byte, nameLen)
	if err := d.readFull(nameBytes, "name"); err != nil {
		return Frame{}, err
	}
	if !utf8.Valid(nameBytes) {
		return Frame{}, d.fail("frame name is not UTF-8")
	}
	var n4 [4]byte
	if err := d.readFull(n4[:], "data length"); err != nil {
		return Frame{}, err
	}
	dataLen := binary.BigEndian.Uint32(n4[:])
	if dataLen > MaxData {
		return Frame{}, d.fail("frame data of %d bytes", dataLen)
	}
	f := Frame{Kind: kind, Name: string(nameBytes)}
	if err := d.order(f); err != nil {
		return Frame{}, err
	}
	f.Data = make([]byte, dataLen)
	if err := d.readFull(f.Data, "data"); err != nil {
		return Frame{}, err
	}
	return f, nil
}

// order checks f against the state and advances it.
func (d *Decoder) order(f Frame) error {
	switch {
	case d.state == wantManifest && f.Kind == Manifest:
		d.state = betweenTables
	case d.state == betweenTables && f.Kind == TableStart:
		if d.tables[f.Name] {
			return d.fail("table %q appears twice", f.Name)
		}
		if len(d.tables) >= maxTables {
			return d.fail("more than %d tables", maxTables)
		}
		d.tables[f.Name] = true
		d.state, d.table = inTable, f.Name
	case d.state == inTable && f.Kind == Data:
	case d.state == inTable && f.Kind == TableEnd:
		if f.Name != d.table {
			return d.fail("table end %q inside table %q", f.Name, d.table)
		}
		d.state, d.table = betweenTables, ""
	case d.state == betweenTables && f.Kind == Sequences:
		d.state = afterSequences
	case d.state == afterSequences && f.Kind == File:
	case d.state == afterSequences && f.Kind == End:
		d.state = done
	default:
		return d.fail("frame %q out of order", f.Kind)
	}
	return nil
}
