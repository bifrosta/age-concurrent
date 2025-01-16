package stream

import (
	"crypto/cipher"
	"io"
	"runtime"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

const ChunkSize = 64 * 1024

const (
	encChunkSize  = ChunkSize + chacha20poly1305.Overhead
	lastChunkFlag = 0x01
)

func incNonce(nonce *[chacha20poly1305.NonceSize]byte) {
	for i := len(nonce) - 2; i >= 0; i-- {
		nonce[i]++
		if nonce[i] != 0 {
			break
		} else if i == 0 {
			// The counter is 88 bits, this is unreachable.
			panic("stream: chunk counter wrapped around")
		}
	}
}

func setLastChunkFlag(nonce *[chacha20poly1305.NonceSize]byte) {
	nonce[len(nonce)-1] = lastChunkFlag
}

type Writer struct {
	a          cipher.AEAD
	dest       io.Writer
	concurrent int

	cleartext []byte
	encrypted []byte
	results   [][]byte

	nonce [chacha20poly1305.NonceSize]byte
}

func NewWriter(a cipher.AEAD, dest io.Writer, concurrent int) *Writer {
	if concurrent < 1 {
		concurrent = runtime.NumCPU()
	}

	return &Writer{
		a:          a,
		dest:       dest,
		concurrent: concurrent,

		cleartext: make([]byte, 0, (12*concurrent)*ChunkSize),
		encrypted: make([]byte, (12*concurrent)*encChunkSize),
		results:   make([][]byte, 12*concurrent),
	}
}

func (w *Writer) Write(p []byte) (n int, err error) {
	total := len(p)

	for len(p) > 0 {
		n := copy(w.cleartext[len(w.cleartext):cap(w.cleartext)], p)
		w.cleartext = w.cleartext[:len(w.cleartext)+n]

		if len(w.cleartext) >= cap(w.cleartext)-ChunkSize {
			err := w.encrypt(false)
			if err != nil {
				return 0, err
			}
		}

		p = p[n:]
	}

	return total, nil
}

func (w *Writer) Close() error {
	return w.encrypt(true)
}

func (w *Writer) encrypt(last bool) (err error) {
	chunks := len(w.cleartext) / ChunkSize

	var wg sync.WaitGroup

	limiter := make(chan struct{}, w.concurrent)

	// If we're not on the last chunk, we need to subtract one from the chunks
	// count to avoid encrypting the last chunk without marking it as such.
	if !last {
		chunks--
	}

	// If we're on the last chunk and there's no data left after faaning out,
	// we need to subtract one from the chunks count to avoid encrypting the last
	// chunk without marking it as such. It will be picked up by the "last" check
	// later.
	left := len(w.cleartext) - chunks*ChunkSize
	if last && left == 0 {
		chunks--
	}

	if chunks > 0 {
		wg.Add(chunks)

		for i := 0; i < chunks; i++ {
			in := w.cleartext[i*ChunkSize : i*ChunkSize+ChunkSize]
			out := w.encrypted[i*encChunkSize : i*encChunkSize]

			go func(out []byte, in []byte, nonce [chacha20poly1305.NonceSize]byte, i int) {
				limiter <- struct{}{}

				w.results[i] = w.a.Seal(out[:0], nonce[:], in, nil)

				wg.Done()

				<-limiter
			}(out, in, w.nonce, i)

			incNonce(&w.nonce)
		}

		wg.Wait()

		for i := 0; i < chunks; i++ {
			_, err := w.dest.Write(w.results[i])
			if err != nil {
				return err
			}
		}

		n := copy(w.cleartext[0:], w.cleartext[chunks*ChunkSize:])

		w.cleartext = w.cleartext[:n]
	}

	if last {
		setLastChunkFlag(&w.nonce)

		result := w.a.Seal(w.encrypted[:0], w.nonce[:], w.cleartext, nil)
		w.cleartext = w.cleartext[:0]

		_, err = w.dest.Write(result)
	}

	return err
}
