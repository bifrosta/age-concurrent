package stream

import (
	"crypto/cipher"
	"io"
)

type Reader struct {
	a   cipher.AEAD
	src io.Reader
}

func NewReader(a cipher.AEAD, src io.Reader, concurrent int) *Reader {
	return &Reader{
		a:   a,
		src: src,
	}
}

func (r *Reader) Read(p []byte) (n int, err error) {
	return 0, nil
}
