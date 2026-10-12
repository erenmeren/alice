package format_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/rand/v2"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/backup/format"
	"alice/internal/secrets"
)

var (
	pass    = []byte("correct-horse-battery-2026 backup")
	fastKDF = secrets.KDFParams{MemoryKiB: 8 * 1024, Time: 1, Threads: 1}
	meta    = format.Meta{AliceVersion: "1.0.0", CreatedAt: time.Date(2026, 10, 10, 2, 30, 0, 0, time.UTC), Kind: "auto"}
)

// installKey is what the recovery-passphrase step stores: the wrapped key (backup.key) and the sender key (backup.sender).
type installKey struct {
	w secrets.WrappedBackupKey
	s *ecdh.PrivateKey
}

func wrapped(t testing.TB) installKey {
	t.Helper()
	w, s, err := secrets.NewBackupKey(pass, fastKDF)
	require.NoError(t, err)
	return installKey{w: w, s: s}
}

func seal(t testing.TB, k installKey, plain []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	wr, err := format.NewWriter(&out, k.w, k.s, meta)
	require.NoError(t, err)
	_, err = wr.Write(plain)
	require.NoError(t, err)
	require.NoError(t, wr.Close())
	return out.Bytes()
}

// open returns the whole payload, or nil and the error. A caller of the streaming Reader must treat what it read as
// unconfirmed until EOF; openPartial shows what a careless caller would have seen.
func open(file, passphrase []byte) ([]byte, error) {
	got, err := openPartial(file, passphrase)
	if err != nil {
		return nil, err
	}
	return got, nil
}

func openPartial(file, passphrase []byte) ([]byte, error) {
	r, _, err := format.Open(bytes.NewReader(file), passphrase)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func payload(n int) []byte {
	p := make([]byte, n)
	rnd := rand.New(rand.NewPCG(1, uint64(n)))
	for i := range p {
		p[i] = byte(rnd.Uint32())
	}
	return p
}

func TestRoundTrip(t *testing.T) {
	w := wrapped(t)
	for _, n := range []int{0, 1, format.ChunkSize - 1, format.ChunkSize, format.ChunkSize + 1, 3 * format.ChunkSize, 1<<20 + 3} {
		plain := payload(n)
		file := seal(t, w, plain)
		got, err := open(file, pass)
		require.NoError(t, err, "size %d", n)
		assert.Equal(t, plain, got, "size %d", n)
		chunks := n/format.ChunkSize + 1 // a payload that fills its last chunk gets an empty final chunk
		hdr, err := format.ReadHeader(bytes.NewReader(file))
		require.NoError(t, err)
		assert.Equal(t, headerLen(t, file)+n+16*chunks, len(file), "size %d: framing", n)
		assert.Equal(t, meta.Kind, hdr.Kind)
		assert.Equal(t, meta.AliceVersion, hdr.AliceVersion)
		assert.True(t, meta.CreatedAt.Equal(hdr.CreatedAt))
		assert.Equal(t, w.w, hdr.WrappedKey)
		assert.Equal(t, w.w.PublicKey, hdr.Recipient)
		assert.Equal(t, format.ChunkSize, hdr.ChunkSize)
		assert.Len(t, hdr.Ephemeral, 32)
		assert.Len(t, hdr.NoncePrefix, 4)
	}
}

// Small writes, one byte at a time across a chunk boundary, give the same file layout as one large write.
func TestWriteInPieces(t *testing.T) {
	k := wrapped(t)
	plain := payload(format.ChunkSize + 300)
	var out bytes.Buffer
	wr, err := format.NewWriter(&out, k.w, k.s, meta)
	require.NoError(t, err)
	for i := 0; i < len(plain); {
		n := min(1+i%977, len(plain)-i)
		m, err := wr.Write(plain[i : i+n])
		require.NoError(t, err)
		require.Equal(t, n, m)
		i += n
	}
	require.NoError(t, wr.Close())
	got, err := open(out.Bytes(), pass)
	require.NoError(t, err)
	assert.Equal(t, plain, got)
	assert.Equal(t, headerLen(t, out.Bytes())+len(plain)+2*16, out.Len())
}

func headerLen(t testing.TB, file []byte) int {
	t.Helper()
	require.GreaterOrEqual(t, len(file), 14)
	return 14 + int(binary.BigEndian.Uint32(file[10:14]))
}

// TestKnownAnswer rebuilds a file with an independent reference implementation of C7 (written here from the
// primitives, not from the package) and requires byte equality; the committed SHA-256 catches format drift.
// Everything is deterministic: fixed recipient and sender keys, a fixed wrapped-key record (the writer only copies it)
// and a seeded ChaCha8 stream for the ephemeral key and the nonce prefix. testdata/kat_check.py recomputes the same
// hash with pyca/cryptography and Python's json, independent of encoding/json (run by hand, see its docstring).
func TestKnownAnswer(t *testing.T) {
	var kat struct {
		Seed       byte   `json:"seed"`
		PlainSize  int    `json:"plain_size"`
		FileSHA256 string `json:"file_sha256"`
	}
	raw, err := os.ReadFile("testdata/kat-v2.json")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &kat))

	priv, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x42}, 32))
	require.NoError(t, err)
	sender, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x43}, 32))
	require.NoError(t, err)
	w := secrets.WrappedBackupKey{Version: 2, PublicKey: priv.PublicKey().Bytes(), KDF: fastKDF,
		Salt: bytes.Repeat([]byte{1}, 16), Nonce: bytes.Repeat([]byte{2}, 12), Ciphertext: bytes.Repeat([]byte{3}, 48),
		SenderPublicKey: sender.PublicKey().Bytes()}
	plain := payload(kat.PlainSize)
	rnd := func() io.Reader { return rand.NewChaCha8([32]byte{kat.Seed}) }

	var got bytes.Buffer
	wr, err := format.NewWriterWithRand(&got, w, sender, meta, rnd())
	require.NoError(t, err)
	_, err = wr.Write(plain)
	require.NoError(t, err)
	require.NoError(t, wr.Close())

	require.Equal(t, reference(t, w, sender, plain, rnd()), got.Bytes(), "the package and the reference implementation disagree")
	sum := sha256.Sum256(got.Bytes())
	assert.Equal(t, kat.FileSHA256, hex.EncodeToString(sum[:]), "the file bytes changed: a format change needs Version 3")

	r, _, err := format.OpenWithKey(bytes.NewReader(got.Bytes()), priv, sender.PublicKey())
	require.NoError(t, err)
	back, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Equal(t, plain, back)
}

// reference is C7 written out by hand. It never checks that sender matches w.SenderPublicKey, so the forgery test can
// use it as an attacker's writer.
func reference(t testing.TB, w secrets.WrappedBackupKey, sender *ecdh.PrivateKey, plain []byte, rnd io.Reader) []byte {
	t.Helper()
	return referenceAuth(t, w, sender.ECDH, plain, rnd)
}

// referenceAuth is reference with the second Diffie-Hellman supplied by auth (given the recipient public key), so a
// test can compute it from the other side of the agreement.
func referenceAuth(t testing.TB, w secrets.WrappedBackupKey, auth func(*ecdh.PublicKey) ([]byte, error), plain []byte,
	rnd io.Reader) []byte {
	t.Helper()
	seed := make([]byte, 32) // the ephemeral private key: 32 bytes from rnd (GenerateKey ignores its reader since Go 1.26)
	_, err := io.ReadFull(rnd, seed)
	require.NoError(t, err)
	eph, err := ecdh.X25519().NewPrivateKey(seed)
	require.NoError(t, err)
	prefix := make([]byte, 4)
	_, err = io.ReadFull(rnd, prefix)
	require.NoError(t, err)
	recipient, err := ecdh.X25519().NewPublicKey(w.PublicKey)
	require.NoError(t, err)
	shared, err := eph.ECDH(recipient)
	require.NoError(t, err)
	authShared, err := auth(recipient) // the second Diffie-Hellman: origin authentication (R43 row 41)
	require.NoError(t, err)
	salt := append(append(append([]byte{}, eph.PublicKey().Bytes()...), w.PublicKey...), w.SenderPublicKey...)
	key, err := hkdf.Key(sha256.New, append(shared, authShared...), salt, "alice/backup/v2", 32)
	require.NoError(t, err)

	hj, err := json.Marshal(struct {
		AliceVersion string                   `json:"alice_version"`
		CreatedAt    string                   `json:"created_at"`
		Kind         string                   `json:"kind"`
		Recipient    []byte                   `json:"recipient"`
		Ephemeral    []byte                   `json:"ephemeral"`
		WrappedKey   secrets.WrappedBackupKey `json:"wrapped_key"`
		ChunkSize    int                      `json:"chunk_size"`
		NoncePrefix  []byte                   `json:"nonce_prefix"`
	}{meta.AliceVersion, meta.CreatedAt.Format(time.RFC3339), meta.Kind, w.PublicKey, eph.PublicKey().Bytes(), w,
		format.ChunkSize, prefix})
	require.NoError(t, err)
	var out bytes.Buffer
	out.WriteString("ALICEBK1")
	out.Write(binary.BigEndian.AppendUint16(nil, 2))
	out.Write(binary.BigEndian.AppendUint32(nil, uint32(len(hj))))
	out.Write(hj)
	hh := sha256.Sum256(out.Bytes())

	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	for i := uint64(0); ; i++ {
		// A chunk is final when fewer than ChunkSize bytes remain before sealing it, so a payload that ends on a
		// chunk boundary is followed by an empty final chunk.
		final := len(plain) < format.ChunkSize
		n := min(format.ChunkSize, len(plain))
		flag := byte(0)
		if final {
			flag = 1
		}
		nonce := binary.BigEndian.AppendUint64(append([]byte{}, prefix...), i)
		out.Write(gcm.Seal(nil, nonce, plain[:n], append(hh[:], flag)))
		plain = plain[n:]
		if final {
			return out.Bytes()
		}
	}
}

func TestHeaderCarriesNoPayloadOrSecret(t *testing.T) {
	w := wrapped(t)
	canary := []byte("CANARY-installation-ALICE-7F3K-host-alice01")
	file := seal(t, w, bytes.Repeat(canary, 100))
	hdr := file[:headerLen(t, file)]
	assert.NotContains(t, string(hdr), "CANARY")
	assert.NotContains(t, string(file), string(pass))
	assert.NotContains(t, string(file), "CANARY")
	for _, enc := range []func([]byte) string{hex.EncodeToString, base64.StdEncoding.EncodeToString, func(b []byte) string { return string(b) }} {
		assert.NotContains(t, string(file), enc(w.s.Bytes()), "the sender private key is never in the file")
	}
}

func TestWrongPassphrase(t *testing.T) {
	file := seal(t, wrapped(t), payload(1000))
	_, err := open(file, []byte("not the passphrase at all"))
	require.ErrorIs(t, err, format.ErrDecrypt)
	require.ErrorIs(t, err, secrets.ErrDecrypt, "the cause stays reachable")
	assert.NotContains(t, err.Error(), "not the passphrase")
}

// R43 row 41 (pre-flight S-2): whoever copied the clear wrapped key of a genuine file cannot build a file that the
// passphrase opens; without the installation's sender private key the second Diffie-Hellman differs.
func TestForgedBackupWithCopiedWrappedKeyFails(t *testing.T) {
	k := wrapped(t)
	hdr, err := format.ReadHeader(bytes.NewReader(seal(t, k, payload(10))))
	require.NoError(t, err)
	attacker, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x66}, 32))
	require.NoError(t, err)
	plain := []byte("CANARY a chosen master.key and administrators")

	// The control: the reference writer with the real sender key makes a file the passphrase opens.
	genuine := reference(t, hdr.WrappedKey, k.s, plain, rand.NewChaCha8([32]byte{9}))
	got, err := open(genuine, pass)
	require.NoError(t, err)
	require.Equal(t, plain, got)

	// The copied wrapped key unchanged, the attacker's own key for the second Diffie-Hellman.
	forged := reference(t, hdr.WrappedKey, attacker, plain, rand.NewChaCha8([32]byte{9}))
	got, err = openPartial(forged, pass)
	require.ErrorIs(t, err, format.ErrDecrypt)
	assert.Empty(t, got)

	// The copied wrapped key with the attacker's sender public key put in: the passphrase no longer opens it.
	swapped := hdr.WrappedKey
	swapped.SenderPublicKey = attacker.PublicKey().Bytes()
	forged = reference(t, swapped, attacker, plain, rand.NewChaCha8([32]byte{9}))
	got, err = openPartial(forged, pass)
	require.ErrorIs(t, err, format.ErrDecrypt)
	assert.Empty(t, got)

	// Even with the recipient private key (the passphrase holder), a file keyed by another sender is refused.
	priv, err := k.w.Unwrap(pass)
	require.NoError(t, err)
	_, _, err = format.OpenWithKey(bytes.NewReader(forged), priv, k.s.PublicKey())
	require.ErrorIs(t, err, format.ErrDecrypt, "the header names another sender")
}

// TestPassphraseHolderCanForge pins the limit of the origin authentication (KI-14, R43 row 41): X25519 is symmetric
// (S_priv*R_pub = R_priv*S_pub), and the passphrase unwraps R_priv while S_pub is in the clear header, so anyone who
// knows the recovery passphrase can build a file the passphrase opens without the sender private key. The sender key
// stops only a forger who does not know the passphrase (TestForgedBackupWithCopiedWrappedKeyFails).
func TestPassphraseHolderCanForge(t *testing.T) {
	k := wrapped(t)
	hdr, err := format.ReadHeader(bytes.NewReader(seal(t, k, payload(10))))
	require.NoError(t, err)
	priv, err := hdr.WrappedKey.Unwrap(pass) // only the passphrase and the copied header
	require.NoError(t, err)
	sender, err := ecdh.X25519().NewPublicKey(hdr.WrappedKey.SenderPublicKey)
	require.NoError(t, err)
	plain := []byte("CANARY a master.key and administrators chosen by the passphrase holder")
	forged := referenceAuth(t, hdr.WrappedKey, func(*ecdh.PublicKey) ([]byte, error) { return priv.ECDH(sender) },
		plain, rand.NewChaCha8([32]byte{7}))
	got, err := open(forged, pass)
	require.NoError(t, err, "the passphrase holder forges a file the passphrase opens")
	assert.Equal(t, plain, got)
}

func TestWriterRefusesAnotherSenderKey(t *testing.T) {
	k, other := wrapped(t), wrapped(t)
	var out bytes.Buffer
	_, err := format.NewWriter(&out, k.w, other.s, meta)
	require.Error(t, err)
	assert.Zero(t, out.Len(), "nothing written")
	for _, b := range [][]byte{other.s.Bytes(), other.s.PublicKey().Bytes(), k.w.SenderPublicKey} {
		assert.NotContains(t, err.Error(), hex.EncodeToString(b))
		assert.NotContains(t, err.Error(), base64.StdEncoding.EncodeToString(b))
	}
	_, err = format.NewWriter(&out, k.w, nil, meta)
	require.Error(t, err)
}

// The writer refuses to make a file its own reader would refuse.
func TestWriterRefusesAHeaderOutsideTheBounds(t *testing.T) {
	k := wrapped(t)
	weak, ws, err := secrets.NewBackupKey(pass, secrets.KDFParams{MemoryKiB: 64, Time: 1, Threads: 1})
	require.NoError(t, err)
	v1 := k.w
	v1.Version = 1
	for name, c := range map[string]struct {
		w secrets.WrappedBackupKey
		s *ecdh.PrivateKey
		m format.Meta
	}{
		"kind":          {k.w, k.s, format.Meta{AliceVersion: "1.0.0", CreatedAt: meta.CreatedAt, Kind: "nightly"}},
		"version":       {k.w, k.s, format.Meta{AliceVersion: "1.0", CreatedAt: meta.CreatedAt, Kind: "auto"}},
		"no time":       {k.w, k.s, format.Meta{AliceVersion: "1.0.0", Kind: "auto"}},
		"weak kdf":      {weak, ws, meta},
		"wrapped key 1": {v1, k.s, meta},
	} {
		var out bytes.Buffer
		_, err := format.NewWriter(&out, c.w, c.s, c.m)
		assert.ErrorIs(t, err, format.ErrHeader, name)
		assert.Zero(t, out.Len(), name)
	}
	for _, m := range []format.Meta{
		{AliceVersion: "dev", CreatedAt: meta.CreatedAt, Kind: "manual"},
		{AliceVersion: "1.0.0-rc.2", CreatedAt: meta.CreatedAt.In(time.FixedZone("TRT", 3*3600)), Kind: "pre-restore"},
		{AliceVersion: "1.0.1", CreatedAt: meta.CreatedAt, Kind: "pre-upgrade-1.0.0-rc.3"},
	} {
		_, err := format.NewWriter(io.Discard, k.w, k.s, m)
		assert.NoError(t, err, "%+v", m)
	}
}

func TestNotBackupAndNewer(t *testing.T) {
	file := seal(t, wrapped(t), payload(10))
	newer := append([]byte{}, file...)
	binary.BigEndian.PutUint16(newer[8:10], 3)
	older := append([]byte{}, file...)
	binary.BigEndian.PutUint16(older[8:10], 1) // no format 1 was ever released (R43 row 41)
	for name, c := range map[string]struct {
		in   []byte
		want error
	}{
		"empty":       {nil, format.ErrNotBackup},
		"text":        {[]byte("hello, this is a text file\n"), format.ErrNotBackup},
		"pdf":         {[]byte("%PDF-1.7\n%âãÏÓ\n1 0 obj"), format.ErrNotBackup},
		"magic":       {file[:8], format.ErrNotBackup},
		"magic, ver.": {file[:13], format.ErrNotBackup},
		"newer":       {newer, format.ErrNewerFormat},
		"newer short": {newer[:14], format.ErrNewerFormat},
		"older":       {older, format.ErrHeader},
	} {
		_, err := open(c.in, pass)
		assert.ErrorIs(t, err, c.want, name)
	}
}

// F-81: one flipped byte anywhere fails; no altered plaintext is ever returned.
func TestEveryFlippedByteFails(t *testing.T) {
	w := wrapped(t)
	plain := payload(2*format.ChunkSize + 1000)
	file := seal(t, w, plain)
	hl := headerLen(t, file)
	chunk := format.ChunkSize + 16
	positions := []int{}
	for i := 0; i < hl; i++ { // every header byte: magic, version, length, JSON (KDF, salt, keys, prefix)
		positions = append(positions, i)
	}
	for _, b := range []int{hl, hl + chunk, hl + 2*chunk} { // around every chunk boundary
		for d := -16; d < 16; d++ {
			if p := b + d; p >= hl && p < len(file) {
				positions = append(positions, p)
			}
		}
	}
	positions = append(positions, hl+chunk/2, len(file)-1)
	for _, p := range positions {
		bad := append([]byte{}, file...)
		bad[p] ^= 0x01
		partial, err := openPartial(bad, pass)
		require.Error(t, err, "flipped byte %d was accepted", p)
		assert.True(t, bytes.HasPrefix(plain, partial), "byte %d: only authenticated chunks of the original are ever returned", p)
		assert.Less(t, len(partial), len(plain), "byte %d", p)
		got, err := open(bad, pass)
		assert.Nil(t, got)
		assert.True(t, errors.Is(err, format.ErrNotBackup) || errors.Is(err, format.ErrNewerFormat) ||
			errors.Is(err, format.ErrHeader) || errors.Is(err, format.ErrDecrypt) || errors.Is(err, format.ErrTruncated),
			"byte %d: unexpected error %v", p, err)
	}
}

// F-82 and B-2: truncation anywhere, a missing final chunk, reordered or foreign chunks, trailing data.
func TestTruncationAndReorderFail(t *testing.T) {
	w := wrapped(t)
	plain := payload(3*format.ChunkSize + 5)
	file := seal(t, w, plain)
	other := seal(t, w, payload(3*format.ChunkSize+5)) // same recipient, another ephemeral key
	hl, chunk := headerLen(t, file), format.ChunkSize+16
	c := func(f []byte, i int) []byte { return f[hl+i*chunk : min(hl+(i+1)*chunk, len(f))] }
	cases := map[string]struct {
		in   []byte
		want error
	}{
		"inside header":        {file[:hl-1], format.ErrHeader},
		"no chunk":             {file[:hl], format.ErrTruncated},
		"inside first chunk":   {file[:hl+100], format.ErrDecrypt},
		"inside the tag":       {file[:hl+10], format.ErrTruncated},
		"at a chunk boundary":  {file[:hl+2*chunk], format.ErrTruncated},
		"final chunk removed":  {file[:hl+3*chunk], format.ErrTruncated},
		"one byte short":       {file[:len(file)-1], format.ErrDecrypt},
		"swapped chunks":       {concat(file[:hl], c(file, 1), c(file, 0), c(file, 2), c(file, 3)), format.ErrDecrypt},
		"foreign chunk":        {concat(file[:hl], c(other, 0), c(file, 1), c(file, 2), c(file, 3)), format.ErrDecrypt},
		"foreign header":       {concat(other[:hl], file[hl:]), format.ErrDecrypt},
		"duplicated chunk":     {concat(file[:hl], c(file, 0), c(file, 0), c(file, 1), c(file, 2), c(file, 3)), format.ErrDecrypt},
		"trailing data":        {concat(file, []byte{0}), format.ErrDecrypt},
		"final chunk repeated": {concat(file, c(file, 3)), format.ErrDecrypt},
	}
	for name, tc := range cases {
		partial, err := openPartial(tc.in, pass)
		assert.ErrorIs(t, err, tc.want, name)
		assert.True(t, bytes.HasPrefix(plain, partial), name)
		got, err := open(tc.in, pass)
		assert.Error(t, err, name)
		assert.Nil(t, got, name)
	}
}

// eofOnce returns io.EOF once at the end of its first part and then serves the second part: a stream that has
// bytes after what looked like its end.
type eofOnce struct {
	first, second *bytes.Reader
	sent          bool
}

func (e *eofOnce) Read(p []byte) (int, error) {
	if e.first.Len() > 0 {
		return e.first.Read(p)
	}
	if !e.sent {
		e.sent = true
		return 0, io.EOF
	}
	return e.second.Read(p)
}

func TestDataAfterTheFinalChunk(t *testing.T) {
	k := wrapped(t)
	plain := payload(1000)
	file := seal(t, k, plain)
	r, _, err := format.Open(&eofOnce{first: bytes.NewReader(file), second: bytes.NewReader([]byte("x"))}, pass)
	require.NoError(t, err)
	_, err = io.ReadAll(r)
	require.ErrorIs(t, err, format.ErrTrailingData)
	_, again := r.Read(make([]byte, 10))
	assert.Equal(t, err, again, "a failed Read keeps returning the same error")
}

func TestOpenWithKeyChecksTheKeys(t *testing.T) {
	k := wrapped(t)
	file := seal(t, k, payload(100))
	priv, err := k.w.Unwrap(pass)
	require.NoError(t, err)
	other := wrapped(t)
	otherPriv, err := other.w.Unwrap(pass)
	require.NoError(t, err)

	_, _, err = format.OpenWithKey(bytes.NewReader(file), otherPriv, k.s.PublicKey())
	assert.ErrorIs(t, err, format.ErrDecrypt, "another recipient")
	_, _, err = format.OpenWithKey(bytes.NewReader(file), priv, other.s.PublicKey())
	assert.ErrorIs(t, err, format.ErrDecrypt, "another sender")
	_, _, err = format.OpenWithKey(bytes.NewReader(file), priv, nil)
	assert.ErrorIs(t, err, format.ErrDecrypt, "no sender")
	_, _, err = format.OpenWithKey(bytes.NewReader(file), nil, k.s.PublicKey())
	assert.ErrorIs(t, err, format.ErrDecrypt, "no key")
	_, _, err = format.OpenWithKey(bytes.NewReader([]byte("nope")), priv, k.s.PublicKey())
	assert.ErrorIs(t, err, format.ErrNotBackup)
	r, hdr, err := format.OpenWithKey(bytes.NewReader(file), priv, k.s.PublicKey())
	require.NoError(t, err)
	assert.Equal(t, "auto", hdr.Kind)
	got, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Equal(t, payload(100), got)
	n, err := r.Read(make([]byte, 1))
	assert.Zero(t, n)
	assert.Equal(t, io.EOF, err, "EOF stays EOF")
}

func concat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func deepCopy(t testing.TB, m map[string]any) map[string]any {
	t.Helper()
	b, err := json.Marshal(m)
	require.NoError(t, err)
	var out map[string]any
	require.NoError(t, json.Unmarshal(b, &out))
	return out
}

// FuzzBackupHeader's bounds, as a table (§25.6: a hostile header never makes Argon2 or the reader allocate unbounded memory).
func TestHeaderBounds(t *testing.T) {
	w := wrapped(t)
	file := seal(t, w, payload(10))
	hl := headerLen(t, file)
	var h map[string]any
	require.NoError(t, json.Unmarshal(file[14:hl], &h))
	mutate := func(f func(map[string]any)) []byte {
		c := deepCopy(t, h)
		f(c)
		j, err := json.Marshal(c)
		require.NoError(t, err)
		out := append([]byte{}, file[:10]...)
		out = binary.BigEndian.AppendUint32(out, uint32(len(j)))
		return append(append(out, j...), file[hl:]...)
	}
	wk := func(m map[string]any) map[string]any { return m["wrapped_key"].(map[string]any) }
	kdf := func(k string, v float64) func(map[string]any) {
		return func(m map[string]any) { wk(m)["kdf"].(map[string]any)[k] = v }
	}
	// The control: the same re-encoding without a change parses, so every case below fails for its own reason.
	_, err := format.ReadHeader(bytes.NewReader(mutate(func(map[string]any) {})))
	require.NoError(t, err)
	_, err = format.ReadHeader(bytes.NewReader(mutate(kdf("memory_kib", format.MaxKDFMemoryKiB))))
	require.NoError(t, err, "the upper bounds are inclusive")
	_, err = format.ReadHeader(bytes.NewReader(mutate(func(m map[string]any) {
		m["alice_version"] = "dev"
		m["kind"] = "pre-upgrade-1.2.3-rc.4"
		wk(m)["kdf"] = map[string]any{"memory_kib": format.MinKDFMemoryKiB, "time": format.MaxKDFTime, "threads": format.MaxKDFThreads}
	})))
	require.NoError(t, err)

	cases := map[string][]byte{
		"memory 4 GiB":           mutate(kdf("memory_kib", 4<<20)),
		"memory 256 MiB + 1":     mutate(kdf("memory_kib", format.MaxKDFMemoryKiB+1)),
		"memory 1 KiB":           mutate(kdf("memory_kib", 1)),
		"memory 8 MiB - 1":       mutate(kdf("memory_kib", format.MinKDFMemoryKiB-1)),
		"memory negative":        mutate(kdf("memory_kib", -1)),
		"1000 iterations":        mutate(kdf("time", 1000)),
		"11 iterations":          mutate(kdf("time", 11)),
		"0 iterations":           mutate(kdf("time", 0)),
		"64 lanes":               mutate(kdf("threads", 64)),
		"17 lanes":               mutate(kdf("threads", 17)),
		"0 lanes":                mutate(kdf("threads", 0)),
		"300 lanes":              mutate(kdf("threads", 300)),
		"1 MiB chunks":           mutate(func(m map[string]any) { m["chunk_size"] = 1 << 20 }),
		"unknown field":          mutate(func(m map[string]any) { m["extra"] = true }),
		"unknown wrapped field":  mutate(func(m map[string]any) { wk(m)["extra"] = 1 }),
		"unknown kdf field":      mutate(func(m map[string]any) { wk(m)["kdf"].(map[string]any)["extra"] = 1 }),
		"missing field":          mutate(func(m map[string]any) { delete(m, "ephemeral") }),
		"null field":             mutate(func(m map[string]any) { m["nonce_prefix"] = nil }),
		"missing kdf":            mutate(func(m map[string]any) { delete(wk(m), "kdf") }),
		"missing kdf time":       mutate(func(m map[string]any) { delete(wk(m)["kdf"].(map[string]any), "time") }),
		"missing created_at":     mutate(func(m map[string]any) { delete(m, "created_at") }),
		"recipient mismatch":     mutate(func(m map[string]any) { m["recipient"] = m["ephemeral"] }),
		"wrapped key v1":         mutate(func(m map[string]any) { wk(m)["version"] = 1 }),
		"no sender key":          mutate(func(m map[string]any) { delete(wk(m), "sender_public_key") }),
		"sender is recipient":    mutate(func(m map[string]any) { wk(m)["sender_public_key"] = m["recipient"] }),
		"short sender key":       mutate(func(m map[string]any) { wk(m)["sender_public_key"] = "AAAA" }),
		"short ephemeral":        mutate(func(m map[string]any) { m["ephemeral"] = "AAAA" }),
		"short salt":             mutate(func(m map[string]any) { wk(m)["salt"] = "AAAA" }),
		"short nonce":            mutate(func(m map[string]any) { wk(m)["nonce"] = "AAAA" }),
		"short ciphertext":       mutate(func(m map[string]any) { wk(m)["ciphertext"] = "AAAA" }),
		"short nonce prefix":     mutate(func(m map[string]any) { m["nonce_prefix"] = "AAA=" }),
		"bad base64":             mutate(func(m map[string]any) { m["nonce_prefix"] = "!!!!" }),
		"bad kind":               mutate(func(m map[string]any) { m["kind"] = "../../etc" }),
		"bad alice version":      mutate(func(m map[string]any) { m["alice_version"] = "1.0.0\n" }),
		"bad time":               mutate(func(m map[string]any) { m["created_at"] = "yesterday" }),
		"number as string":       mutate(func(m map[string]any) { m["chunk_size"] = "65536" }),
		"array":                  append(append(append([]byte{}, file[:10]...), 0, 0, 0, 2), '[', ']'),
		"two objects":            mutate2(t, file, hl, func(j []byte) []byte { return append(j, []byte(" {}")...) }),
		"header length 0":        append(append(append([]byte{}, file[:10]...), 0, 0, 0, 0), file[hl:]...),
		"header length 65537":    append(append([]byte{}, file[:10]...), 0, 1, 0, 1),
		"header length 4 GiB":    append(append([]byte{}, file[:10]...), 0xff, 0xff, 0xff, 0xff),
		"header longer than all": append(append([]byte{}, file[:10]...), 0, 0, 0x10, 0),
	}
	for name, f := range cases {
		_, err := format.ReadHeader(bytes.NewReader(f))
		assert.ErrorIs(t, err, format.ErrHeader, name)
		_, err = open(f, pass)
		assert.ErrorIs(t, err, format.ErrHeader, name)
	}
}

func mutate2(t testing.TB, file []byte, hl int, f func([]byte) []byte) []byte {
	t.Helper()
	j := f(append([]byte{}, file[14:hl]...))
	out := append([]byte{}, file[:10]...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(j)))
	return append(append(out, j...), file[hl:]...)
}

func TestReaderHoldsOneChunk(t *testing.T) {
	w := wrapped(t)
	r, _, err := format.Open(bytes.NewReader(seal(t, w, payload(5*format.ChunkSize))), pass)
	require.NoError(t, err)
	_, err = io.Copy(io.Discard, r)
	require.NoError(t, err)
	assert.LessOrEqual(t, r.BufferCap(), format.ChunkSize+16)
}

func TestWriterRejectsUseAfterClose(t *testing.T) {
	var out bytes.Buffer
	k := wrapped(t)
	wr, err := format.NewWriter(&out, k.w, k.s, meta)
	require.NoError(t, err)
	require.NoError(t, wr.Close())
	require.NoError(t, wr.Close()) // idempotent
	_, err = wr.Write([]byte("x"))
	require.Error(t, err)
	got, err := open(out.Bytes(), pass)
	require.NoError(t, err)
	assert.Empty(t, got, "an empty payload is one final chunk")
}

// failAfter accepts n bytes and then fails every write.
type failAfter struct {
	n   int
	err error
}

func (f *failAfter) Write(p []byte) (int, error) {
	if len(p) > f.n {
		k := f.n
		f.n = 0
		return k, f.err
	}
	f.n -= len(p)
	return len(p), nil
}

func TestWriterErrorsAreSticky(t *testing.T) {
	k := wrapped(t)
	boom := errors.New("disk full")
	_, err := format.NewWriter(&failAfter{n: 5, err: boom}, k.w, k.s, meta)
	require.ErrorIs(t, err, boom, "the header write fails")

	wr, err := format.NewWriter(&failAfter{n: 4096, err: boom}, k.w, k.s, meta)
	require.NoError(t, err)
	_, err = wr.Write(payload(format.ChunkSize + 1))
	require.ErrorIs(t, err, boom)
	_, err = wr.Write([]byte("more"))
	require.ErrorIs(t, err, boom)
	require.ErrorIs(t, wr.Close(), boom)

	hl := headerLen(t, seal(t, k, nil))
	wr, err = format.NewWriter(&failAfter{n: hl + 10, err: boom}, k.w, k.s, meta)
	require.NoError(t, err)
	_, err = wr.Write(payload(100))
	require.NoError(t, err, "buffered")
	require.ErrorIs(t, wr.Close(), boom, "the final chunk write fails")
}

func TestErrorsNameNoKeyMaterial(t *testing.T) {
	k := wrapped(t)
	file := seal(t, k, payload(10))
	hl := headerLen(t, file)
	bad := append([]byte{}, file...)
	bad[hl-3] ^= 0x20 // inside the last base64 field (nonce_prefix)
	_, err := format.ReadHeader(bytes.NewReader(bad))
	if err != nil {
		for _, b := range [][]byte{k.w.PublicKey, k.w.SenderPublicKey, k.w.Ciphertext, k.w.Salt} {
			assert.False(t, strings.Contains(err.Error(), base64.StdEncoding.EncodeToString(b)))
		}
	}
	_, err = open(file, []byte("wrong passphrase, long enough"))
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "wrong passphrase")
}

// Every field of the header is required, at every level.
func TestEveryHeaderFieldIsRequired(t *testing.T) {
	file := seal(t, wrapped(t), payload(10))
	hl := headerLen(t, file)
	var h map[string]any
	require.NoError(t, json.Unmarshal(file[14:hl], &h))
	paths := [][]string{}
	var walk func(prefix []string, m map[string]any)
	walk = func(prefix []string, m map[string]any) {
		for k, v := range m {
			p := append(append([]string{}, prefix...), k)
			paths = append(paths, p)
			if sub, ok := v.(map[string]any); ok {
				walk(p, sub)
			}
		}
	}
	walk(nil, h)
	require.Len(t, paths, 8+7+3, "every field of C7")
	for _, p := range paths {
		for _, null := range []bool{false, true} {
			c := deepCopy(t, h)
			m := c
			for _, k := range p[:len(p)-1] {
				m = m[k].(map[string]any)
			}
			if null {
				m[p[len(p)-1]] = nil
			} else {
				delete(m, p[len(p)-1])
			}
			j, err := json.Marshal(c)
			require.NoError(t, err)
			_, err = format.ReadHeader(bytes.NewReader(mutate2(t, file, hl, func([]byte) []byte { return j })))
			assert.ErrorIs(t, err, format.ErrHeader, "%v null=%v", p, null)
			if !null {
				assert.ErrorContains(t, err, strings.Join(p, ".")+" is missing")
			}
		}
	}
}

// An ephemeral key of low order gives no shared secret: the file is refused, nothing panics.
func TestLowOrderEphemeralKey(t *testing.T) {
	k := wrapped(t)
	file := seal(t, k, payload(10))
	hl := headerLen(t, file)
	var h map[string]any
	require.NoError(t, json.Unmarshal(file[14:hl], &h))
	h["ephemeral"] = base64.StdEncoding.EncodeToString(make([]byte, 32))
	j, err := json.Marshal(h)
	require.NoError(t, err)
	bad := mutate2(t, file, hl, func([]byte) []byte { return j })
	_, err = format.ReadHeader(bytes.NewReader(bad))
	require.NoError(t, err)
	_, err = open(bad, pass)
	require.ErrorIs(t, err, format.ErrDecrypt)
}

type errReader struct {
	r   io.Reader
	err error
}

func (e *errReader) Read(p []byte) (int, error) {
	n, err := e.r.Read(p)
	if err == io.EOF {
		return n, e.err
	}
	return n, err
}

// A read error of the underlying stream is returned as it is, never as a format verdict.
func TestReadErrorsPassThrough(t *testing.T) {
	k := wrapped(t)
	file := seal(t, k, payload(2*format.ChunkSize+10))
	hl := headerLen(t, file)
	boom := errors.New("I/O error")
	for _, cut := range []int{5, hl - 5, hl + 100, hl + format.ChunkSize + 16, hl + 2*(format.ChunkSize+16) - 1, len(file)} {
		r, _, err := format.Open(&errReader{r: bytes.NewReader(file[:cut]), err: boom}, pass)
		if err == nil {
			_, err = io.ReadAll(r)
		}
		require.ErrorIs(t, err, boom, "cut %d", cut)
		for _, e := range []error{format.ErrNotBackup, format.ErrHeader, format.ErrDecrypt, format.ErrTruncated, format.ErrTrailingData} {
			assert.NotErrorIs(t, err, e, "cut %d", cut)
		}
	}
}

// The ephemeral key and the nonce prefix come from the random source; a failing source makes no file.
func TestWriterNeedsRandomness(t *testing.T) {
	k := wrapped(t)
	for _, n := range []int{0, 31, 32, 35} {
		var out bytes.Buffer
		_, err := format.NewWriterWithRand(&out, k.w, k.s, meta, bytes.NewReader(make([]byte, n)))
		require.Error(t, err, "%d random bytes", n)
		assert.Zero(t, out.Len())
	}
	// Two files of the same payload differ (another ephemeral key and nonce prefix).
	assert.NotEqual(t, seal(t, k, payload(10)), seal(t, k, payload(10)))
}

// Task 1 review I-1: a backup keyed with the composed passphrase opens when the restore types it decomposed.
func TestOpenNormalisesThePassphrase(t *testing.T) {
	w, s, err := secrets.NewBackupKey([]byte("çağrı İşgüzar ölçü é yedek parolası"), fastKDF)
	require.NoError(t, err)
	plain := payload(1000)
	file := seal(t, installKey{w: w, s: s}, plain)
	got, err := open(file, []byte("çağrı İşgüzar ölçü é yedek parolası"))
	require.NoError(t, err)
	assert.Equal(t, plain, got)
}
