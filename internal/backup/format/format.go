// Package format is the encrypted backup container (R4, SEC-048; C7; R43 row 41): a clear, bounded header that carries
// the passphrase-wrapped backup key, then the payload in 64 KiB AES-256-GCM chunks with a final flag. The file key is
// HKDF-SHA256 of two X25519 agreements: an ephemeral key with the recipient (the backup key) and the installation's
// sender key with the recipient, so only a holder of the sender private key can make a file the passphrase opens.
//
// The package is pure: it works on io.Reader and io.Writer only and never opens a file, a socket or a database.
package format

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"alice/internal/secrets"
)

// The container constants of C7.
const (
	Magic        = "ALICEBK1"
	Version      = 2
	ChunkSize    = 65536
	MaxHeaderLen = 65536
)

const (
	prefixSize = len(Magic) + 2 + 4 // magic, version, header length
	tagSize    = 16
	fileKeyLen = 32
	hkdfInfo   = "alice/backup/v2"
)

// Errors of the container (C7). Every error of this package wraps exactly one of them.
var (
	ErrNotBackup    = errors.New("format: not an Alice backup")
	ErrNewerFormat  = errors.New("format: the backup was made by a newer Alice")
	ErrHeader       = errors.New("format: the backup header is invalid")
	ErrDecrypt      = errors.New("format: the passphrase is wrong or the backup is damaged")
	ErrTruncated    = errors.New("format: the backup ends before its final chunk")
	ErrTrailingData = errors.New("format: data after the final chunk of the backup")
)

var errClosed = errors.New("format: write to a closed backup writer")

// WrappedKey is the passphrase-wrapped backup key carried in the clear header.
type WrappedKey = secrets.WrappedBackupKey

// Meta is the clear metadata of a backup. It holds no installation ID and no host name.
type Meta struct {
	AliceVersion string
	CreatedAt    time.Time
	Kind         string
}

// Header is the parsed clear header.
type Header struct {
	Meta
	Recipient   []byte
	Ephemeral   []byte
	WrappedKey  WrappedKey
	ChunkSize   int
	NoncePrefix []byte
}

// headerJSON is the header as written: this field order and these tags are the format.
type headerJSON struct {
	AliceVersion string     `json:"alice_version"`
	CreatedAt    string     `json:"created_at"`
	Kind         string     `json:"kind"`
	Recipient    []byte     `json:"recipient"`
	Ephemeral    []byte     `json:"ephemeral"`
	WrappedKey   WrappedKey `json:"wrapped_key"`
	ChunkSize    int        `json:"chunk_size"`
	NoncePrefix  []byte     `json:"nonce_prefix"`
}

// The header as read: every field is a pointer so that a missing (or null) field is refused.
type (
	headerIn struct {
		AliceVersion *string    `json:"alice_version"`
		CreatedAt    *string    `json:"created_at"`
		Kind         *string    `json:"kind"`
		Recipient    *[]byte    `json:"recipient"`
		Ephemeral    *[]byte    `json:"ephemeral"`
		WrappedKey   *wrappedIn `json:"wrapped_key"`
		ChunkSize    *int       `json:"chunk_size"`
		NoncePrefix  *[]byte    `json:"nonce_prefix"`
	}
	wrappedIn struct {
		Version         *int    `json:"version"`
		PublicKey       *[]byte `json:"public_key"`
		KDF             *kdfIn  `json:"kdf"`
		Salt            *[]byte `json:"salt"`
		Nonce           *[]byte `json:"nonce"`
		Ciphertext      *[]byte `json:"ciphertext"`
		SenderPublicKey *[]byte `json:"sender_public_key"`
	}
	kdfIn struct {
		MemoryKiB *uint32 `json:"memory_kib"`
		Time      *uint32 `json:"time"`
		Threads   *uint8  `json:"threads"`
	}
)

// Writer encrypts a payload into a backup file. Close writes the final chunk; a file without it is refused.
type Writer struct {
	w       io.Writer
	aead    cipher.AEAD
	prefix  []byte
	aadBase [sha256.Size]byte
	buf     []byte // plaintext of the next chunk, at most ChunkSize bytes
	out     []byte // the sealed chunk
	counter uint64
	closed  bool
	err     error
}

// NewWriter writes the header of a backup for the recipient of wrapped, keyed with the installation's sender key,
// and returns a writer for the payload. It refuses a sender whose public half is not wrapped.SenderPublicKey, and a
// header its own reader would refuse.
func NewWriter(w io.Writer, wrapped WrappedKey, sender *ecdh.PrivateKey, m Meta) (*Writer, error) {
	return newWriter(w, wrapped, sender, m, rand.Reader)
}

func newWriter(w io.Writer, wrapped WrappedKey, sender *ecdh.PrivateKey, m Meta, rnd io.Reader) (*Writer, error) {
	if sender == nil || !bytes.Equal(sender.PublicKey().Bytes(), wrapped.SenderPublicKey) {
		return nil, errors.New("format: the sender key does not belong to this backup key")
	}
	seed := make([]byte, keyLen)
	defer clear(seed)
	prefix := make([]byte, prefixLen)
	if _, err := io.ReadFull(rnd, seed); err != nil {
		return nil, fmt.Errorf("format: generate the ephemeral key: %w", err)
	}
	if _, err := io.ReadFull(rnd, prefix); err != nil {
		return nil, fmt.Errorf("format: generate the nonce prefix: %w", err)
	}
	// NewPrivateKey, not GenerateKey: GenerateKey ignores its reader since Go 1.26, and the known-answer test needs
	// a deterministic ephemeral key.
	eph, err := ecdh.X25519().NewPrivateKey(seed)
	if err != nil {
		return nil, fmt.Errorf("format: ephemeral key: %w", err)
	}
	h := Header{
		Meta:        Meta{AliceVersion: m.AliceVersion, CreatedAt: m.CreatedAt.UTC(), Kind: m.Kind},
		Recipient:   bytes.Clone(wrapped.PublicKey),
		Ephemeral:   eph.PublicKey().Bytes(),
		WrappedKey:  wrapped,
		ChunkSize:   ChunkSize,
		NoncePrefix: prefix,
	}
	if err := checkHeader(h); err != nil {
		return nil, err
	}
	recipient, err := ecdh.X25519().NewPublicKey(wrapped.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: recipient key", ErrHeader)
	}
	aead, err := fileCipher(func() ([]byte, []byte, error) {
		a, err := eph.ECDH(recipient)
		if err != nil {
			return nil, nil, err
		}
		b, err := sender.ECDH(recipient)
		return a, b, err
	}, h)
	if err != nil {
		return nil, err
	}
	raw, err := encodeHeader(h)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(raw); err != nil {
		return nil, fmt.Errorf("format: write the backup header: %w", err)
	}
	return &Writer{w: w, aead: aead, prefix: prefix, aadBase: sha256.Sum256(raw),
		buf: make([]byte, 0, ChunkSize), out: make([]byte, 0, ChunkSize+tagSize)}, nil
}

// fileCipher derives the file key from the two shared secrets (C7) and returns its AES-256-GCM. The secrets and the
// key are cleared before it returns (best effort, R43 row 53: the cipher keeps its own key schedule).
func fileCipher(agree func() (shared, auth []byte, err error), h Header) (cipher.AEAD, error) {
	shared, auth, err := agree()
	defer clear(shared)
	defer clear(auth)
	if err != nil {
		return nil, ErrDecrypt // a low-order point: no key can be agreed
	}
	secret := append(append(make([]byte, 0, len(shared)+len(auth)), shared...), auth...)
	defer clear(secret)
	salt := append(append(append(make([]byte, 0, 3*keyLen), h.Ephemeral...), h.Recipient...), h.WrappedKey.SenderPublicKey...)
	key, err := hkdf.Key(sha256.New, secret, salt, hkdfInfo, fileKeyLen)
	if err != nil {
		return nil, fmt.Errorf("format: derive the file key: %w", err)
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("format: file cipher: %w", err)
	}
	return cipher.NewGCM(block)
}

func encodeHeader(h Header) ([]byte, error) {
	j, err := json.Marshal(headerJSON{
		AliceVersion: h.AliceVersion, CreatedAt: h.CreatedAt.UTC().Format(time.RFC3339), Kind: h.Kind,
		Recipient: h.Recipient, Ephemeral: h.Ephemeral, WrappedKey: h.WrappedKey, ChunkSize: h.ChunkSize,
		NoncePrefix: h.NoncePrefix,
	})
	if err != nil {
		return nil, fmt.Errorf("format: encode the backup header: %w", err)
	}
	if len(j) > MaxHeaderLen {
		return nil, fmt.Errorf("%w: header of %d bytes", ErrHeader, len(j))
	}
	out := make([]byte, 0, prefixSize+len(j))
	out = append(out, Magic...)
	out = binary.BigEndian.AppendUint16(out, Version)
	out = binary.BigEndian.AppendUint32(out, uint32(len(j))) //nolint:gosec // bounded by MaxHeaderLen above
	return append(out, j...), nil
}

func chunkNonce(prefix []byte, i uint64) []byte {
	return binary.BigEndian.AppendUint64(append(make([]byte, 0, prefixLen+8), prefix...), i)
}

func chunkAAD(base *[sha256.Size]byte, final bool) []byte {
	flag := byte(0)
	if final {
		flag = 1
	}
	return append(append(make([]byte, 0, sha256.Size+1), base[:]...), flag)
}

// Write buffers p and writes every chunk that is known not to be the last.
func (w *Writer) Write(p []byte) (int, error) {
	if w.closed {
		return 0, errClosed
	}
	if w.err != nil {
		return 0, w.err
	}
	n := 0
	for len(p) > 0 {
		if len(w.buf) == ChunkSize { // more data follows, so this full chunk is not the last
			if err := w.sealChunk(false); err != nil {
				return n, err
			}
		}
		k := copy(w.buf[len(w.buf):ChunkSize], p)
		w.buf = w.buf[:len(w.buf)+k]
		p = p[k:]
		n += k
	}
	return n, nil
}

func (w *Writer) sealChunk(final bool) error {
	w.out = w.aead.Seal(w.out[:0], chunkNonce(w.prefix, w.counter), w.buf, chunkAAD(&w.aadBase, final))
	w.counter++
	clear(w.buf)
	w.buf = w.buf[:0]
	if _, err := w.w.Write(w.out); err != nil {
		w.err = fmt.Errorf("format: write a backup chunk: %w", err)
		return w.err
	}
	return nil
}

// Close writes the final chunk. A payload that ends on a chunk boundary gets an empty final chunk. Close is
// idempotent; it does not close the underlying writer.
func (w *Writer) Close() error {
	if w.closed {
		return w.err
	}
	w.closed = true
	defer func() { clear(w.buf[:cap(w.buf)]) }()
	if w.err != nil {
		return w.err
	}
	if len(w.buf) == ChunkSize {
		if err := w.sealChunk(false); err != nil {
			return err
		}
	}
	return w.sealChunk(true)
}

// ReadHeader reads and validates the clear header. It reads exactly the header bytes from r.
func ReadHeader(r io.Reader) (Header, error) {
	h, _, err := readHeader(r)
	return h, err
}

func readHeader(r io.Reader) (Header, [sha256.Size]byte, error) {
	var none [sha256.Size]byte
	pre := make([]byte, prefixSize)
	if _, err := io.ReadFull(r, pre); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return Header{}, none, ErrNotBackup
		}
		return Header{}, none, fmt.Errorf("format: read the backup header: %w", err)
	}
	if string(pre[:len(Magic)]) != Magic {
		return Header{}, none, ErrNotBackup
	}
	switch v := binary.BigEndian.Uint16(pre[len(Magic):]); {
	case v > Version:
		return Header{}, none, fmt.Errorf("%w (format %d)", ErrNewerFormat, v)
	case v < Version:
		return Header{}, none, fmt.Errorf("%w: format %d", ErrHeader, v)
	}
	n := binary.BigEndian.Uint32(pre[len(Magic)+2:])
	if n < 1 || n > MaxHeaderLen { // checked before anything is allocated
		return Header{}, none, fmt.Errorf("%w: header length %d", ErrHeader, n)
	}
	raw := make([]byte, prefixSize+int(n))
	copy(raw, pre)
	if _, err := io.ReadFull(r, raw[prefixSize:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return Header{}, none, fmt.Errorf("%w: the file ends inside the header", ErrHeader)
		}
		return Header{}, none, fmt.Errorf("format: read the backup header: %w", err)
	}
	h, err := decodeHeader(raw[prefixSize:])
	if err != nil {
		return Header{}, none, err
	}
	if err := checkHeader(h); err != nil {
		return Header{}, none, err
	}
	return h, sha256.Sum256(raw), nil
}

func decodeHeader(j []byte) (Header, error) {
	dec := json.NewDecoder(bytes.NewReader(j))
	dec.DisallowUnknownFields()
	var in headerIn
	if err := dec.Decode(&in); err != nil {
		return Header{}, fmt.Errorf("%w: header JSON: %w", ErrHeader, jsonCause(err))
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Header{}, fmt.Errorf("%w: data after the header JSON", ErrHeader)
	}
	missing := func(name string) error { return fmt.Errorf("%w: %s is missing", ErrHeader, name) }
	switch {
	case in.AliceVersion == nil:
		return Header{}, missing("alice_version")
	case in.CreatedAt == nil:
		return Header{}, missing("created_at")
	case in.Kind == nil:
		return Header{}, missing("kind")
	case in.Recipient == nil:
		return Header{}, missing("recipient")
	case in.Ephemeral == nil:
		return Header{}, missing("ephemeral")
	case in.WrappedKey == nil:
		return Header{}, missing("wrapped_key")
	case in.ChunkSize == nil:
		return Header{}, missing("chunk_size")
	case in.NoncePrefix == nil:
		return Header{}, missing("nonce_prefix")
	}
	wk := in.WrappedKey
	switch {
	case wk.Version == nil:
		return Header{}, missing("wrapped_key.version")
	case wk.PublicKey == nil:
		return Header{}, missing("wrapped_key.public_key")
	case wk.KDF == nil:
		return Header{}, missing("wrapped_key.kdf")
	case wk.Salt == nil:
		return Header{}, missing("wrapped_key.salt")
	case wk.Nonce == nil:
		return Header{}, missing("wrapped_key.nonce")
	case wk.Ciphertext == nil:
		return Header{}, missing("wrapped_key.ciphertext")
	case wk.SenderPublicKey == nil:
		return Header{}, missing("wrapped_key.sender_public_key")
	case wk.KDF.MemoryKiB == nil:
		return Header{}, missing("wrapped_key.kdf.memory_kib")
	case wk.KDF.Time == nil:
		return Header{}, missing("wrapped_key.kdf.time")
	case wk.KDF.Threads == nil:
		return Header{}, missing("wrapped_key.kdf.threads")
	}
	created, err := parseCreatedAt(*in.CreatedAt)
	if err != nil {
		return Header{}, err
	}
	return Header{
		Meta:      Meta{AliceVersion: *in.AliceVersion, CreatedAt: created, Kind: *in.Kind},
		Recipient: *in.Recipient,
		Ephemeral: *in.Ephemeral,
		WrappedKey: WrappedKey{Version: *wk.Version, PublicKey: *wk.PublicKey,
			KDF:  secrets.KDFParams{MemoryKiB: *wk.KDF.MemoryKiB, Time: *wk.KDF.Time, Threads: *wk.KDF.Threads},
			Salt: *wk.Salt, Nonce: *wk.Nonce, Ciphertext: *wk.Ciphertext, SenderPublicKey: *wk.SenderPublicKey},
		ChunkSize:   *in.ChunkSize,
		NoncePrefix: *in.NoncePrefix,
	}, nil
}

// jsonCause keeps the kind of a JSON error but drops its text when that could quote header bytes.
func jsonCause(err error) error {
	var syn *json.SyntaxError
	var typ *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syn):
		return fmt.Errorf("syntax error at offset %d", syn.Offset)
	case errors.As(err, &typ):
		return fmt.Errorf("wrong type for %s", typ.Field)
	default:
		return errors.New("not a header object")
	}
}

// Open reads the header, unwraps the backup key with the passphrase and returns a reader of the payload. The
// sender key comes only from the wrapped key the passphrase opened, so a restore needs nothing but the passphrase.
func Open(r io.Reader, passphrase []byte) (*Reader, Header, error) {
	h, aadBase, err := readHeader(r)
	if err != nil {
		return nil, Header{}, err
	}
	priv, err := h.WrappedKey.Unwrap(passphrase)
	if err != nil {
		return nil, Header{}, fmt.Errorf("%w: %w", ErrDecrypt, err)
	}
	sender, err := ecdh.X25519().NewPublicKey(h.WrappedKey.SenderPublicKey)
	if err != nil {
		return nil, Header{}, ErrDecrypt
	}
	rd, err := newReader(r, h, aadBase, priv, sender)
	if err != nil {
		return nil, Header{}, err
	}
	return rd, h, nil
}

// OpenWithKey is Open with the recipient private key already unwrapped and a sender key the caller trusts. A header
// for another recipient or another sender returns ErrDecrypt.
func OpenWithKey(r io.Reader, priv *ecdh.PrivateKey, sender *ecdh.PublicKey) (*Reader, Header, error) {
	h, aadBase, err := readHeader(r)
	if err != nil {
		return nil, Header{}, err
	}
	rd, err := newReader(r, h, aadBase, priv, sender)
	if err != nil {
		return nil, Header{}, err
	}
	return rd, h, nil
}

func newReader(r io.Reader, h Header, aadBase [sha256.Size]byte, priv *ecdh.PrivateKey, sender *ecdh.PublicKey) (*Reader, error) {
	if priv == nil || sender == nil || !bytes.Equal(priv.PublicKey().Bytes(), h.Recipient) ||
		!bytes.Equal(sender.Bytes(), h.WrappedKey.SenderPublicKey) {
		return nil, ErrDecrypt
	}
	eph, err := ecdh.X25519().NewPublicKey(h.Ephemeral)
	if err != nil {
		return nil, ErrDecrypt
	}
	aead, err := fileCipher(func() ([]byte, []byte, error) {
		a, err := priv.ECDH(eph)
		if err != nil {
			return nil, nil, err
		}
		b, err := priv.ECDH(sender)
		return a, b, err
	}, h)
	if err != nil {
		return nil, err
	}
	return &Reader{r: r, aead: aead, prefix: h.NoncePrefix, aadBase: aadBase, buf: make([]byte, ChunkSize+tagSize)}, nil
}

// Reader decrypts the payload chunk by chunk; it holds at most one chunk in memory. Every byte it returns comes from
// an authenticated chunk, but a caller must treat the payload as complete only when Read returns io.EOF: a damaged
// or truncated file fails at the chunk where the damage is.
type Reader struct {
	r        io.Reader
	aead     cipher.AEAD
	prefix   []byte
	aadBase  [sha256.Size]byte
	buf      []byte // one sealed chunk; opened in place
	plain    []byte // the unread rest of the current chunk, inside buf
	look     [1]byte
	haveLook bool
	counter  uint64
	done     bool
	err      error
}

// Read returns payload bytes. After the final chunk it returns io.EOF; a failure is returned again on every call.
func (r *Reader) Read(p []byte) (int, error) {
	for len(r.plain) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		if r.done {
			r.err = r.checkEnd()
			continue
		}
		r.err = r.nextChunk()
	}
	n := copy(p, r.plain)
	r.plain = r.plain[n:]
	return n, nil
}

// nextChunk reads and opens one chunk. A chunk is final when it is shorter than a full sealed chunk. The writer
// never seals a full chunk as final (a boundary payload gets an empty final chunk), so a full chunk followed by EOF
// is a stream cut at a chunk boundary: ErrTruncated, without opening it.
func (r *Reader) nextChunk() error {
	buf := r.buf[:cap(r.buf)]
	n := 0
	if r.haveLook {
		buf[0] = r.look[0]
		n, r.haveLook = 1, false
	}
	m, err := io.ReadFull(r.r, buf[n:])
	n += m
	final := false
	switch {
	case errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF):
		final = true
	case err != nil:
		return fmt.Errorf("format: read the backup: %w", err)
	default:
		k, lerr := io.ReadFull(r.r, r.look[:])
		switch {
		case k == 1:
			r.haveLook = true
		case errors.Is(lerr, io.EOF):
			return ErrTruncated
		default:
			return fmt.Errorf("format: read the backup: %w", lerr)
		}
	}
	if n < tagSize {
		return ErrTruncated
	}
	plain, err := r.aead.Open(buf[:0], chunkNonce(r.prefix, r.counter), buf[:n], chunkAAD(&r.aadBase, final))
	if err != nil {
		return ErrDecrypt
	}
	r.counter++
	r.plain = plain
	r.done = final
	return nil
}

// checkEnd runs after the final chunk: anything more in the stream is trailing data.
func (r *Reader) checkEnd() error {
	var b [1]byte
	n, err := io.ReadFull(r.r, b[:])
	switch {
	case n > 0:
		return ErrTrailingData
	case errors.Is(err, io.EOF):
		return io.EOF
	default:
		return fmt.Errorf("format: read the backup: %w", err)
	}
}
