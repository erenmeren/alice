package format

import (
	"crypto/ecdh"
	"io"
)

// NewWriterWithRand builds a writer whose ephemeral key and nonce prefix come from rnd (known-answer tests).
func NewWriterWithRand(w io.Writer, wrapped WrappedKey, sender *ecdh.PrivateKey, m Meta, rnd io.Reader) (*Writer, error) {
	return newWriter(w, wrapped, sender, m, rnd)
}

// BufferCap is the capacity of the reader's chunk buffer (the one-chunk memory bound).
func (r *Reader) BufferCap() int { return cap(r.buf) }
