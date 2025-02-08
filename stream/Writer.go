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

type job struct {
	last  bool
	in    []byte
	nonce [chacha20poly1305.NonceSize]byte
	out   chan []byte
}

type Writer struct {
	a cipher.AEAD

	nonce [chacha20poly1305.NonceSize]byte

	inbuffer  []byte
	fill      int
	encrypted chan chan []byte
	reuse     chan []byte
	done      chan error
}

func NewWriter(a cipher.AEAD, dest io.Writer, concurrent int) *Writer {
	if concurrent < 1 {
		concurrent = runtime.NumCPU()
	}

	w := &Writer{
		a: a,

		encrypted: make(chan chan []byte, concurrent),
		done:      make(chan error),
		reuse:     make(chan []byte, concurrent),
	}
	for i := 0; i < concurrent; i++ {
		w.reuse <- make([]byte, ChunkSize+chacha20poly1305.Overhead)
	}
	w.inbuffer = <-w.reuse
	go func() {
		for e := range w.encrypted {
			buffer := <-e

			_, err := dest.Write(buffer)
			if err != nil {
				// FIXME: Deal with this error somehow.
				// Send them on the done channel.
				panic(err)
			}
			w.reuse <- buffer
		}

		close(w.done)
	}()

	var wg sync.WaitGroup
	wg.Add(concurrent)

	go func() {
		wg.Wait()
		close(w.encrypted)
	}()

	return w
}

func (w *Writer) Write(p []byte) (n int, err error) {
	total := len(p)

	for len(p) > 0 {
		if w.fill == ChunkSize {
			in := w.inbuffer[:ChunkSize]
			out := make(chan []byte, 1)
			nonce := w.nonce
			go func() {
				out <- w.a.Seal(in[:0], nonce[:], in, nil)
			}()
			w.encrypted <- out

			// Move to next...
			incNonce(&w.nonce)
			w.fill = 0
			w.inbuffer = <-w.reuse
		}
		n := copy(w.inbuffer[w.fill:ChunkSize], p)
		w.fill += n
		p = p[n:]
	}

	return total, nil
}

func (w *Writer) Close() error {
	in := w.inbuffer[:w.fill]
	out := make(chan []byte, 1)
	nonce := w.nonce
	setLastChunkFlag(&nonce)
	out <- w.a.Seal(in[:0], nonce[:], in, nil)
	w.encrypted <- out

	close(w.encrypted)

	return <-w.done
}
