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
	todo      chan *job
	encrypted chan chan []byte
	reBuf     chan []byte
	reJob     chan *job
	done      chan error
}

func NewWriter(agewriter io.Writer, dest io.Writer, concurrent int) *Writer {
	a := extract[cipher.AEAD](agewriter, "a")

	return newWriter(a, dest, concurrent)
}

func newWriter(a cipher.AEAD, dest io.Writer, concurrent int) *Writer {
	if concurrent < 1 {
		concurrent = runtime.NumCPU()
	}

	w := &Writer{
		a: a,

		inbuffer:  make([]byte, ChunkSize+chacha20poly1305.Overhead),
		todo:      make(chan *job, concurrent),
		encrypted: make(chan chan []byte, concurrent),
		done:      make(chan error),
		reBuf:     make(chan []byte, concurrent), // reuse of blocks
		reJob:     make(chan *job, concurrent),   // reuse of jobs (in shouldn't be)
	}
	for i := 0; i < concurrent; i++ {
		w.reBuf <- make([]byte, ChunkSize+chacha20poly1305.Overhead)
		w.reJob <- &job{out: make(chan []byte, 1)}
	}
	go func() {
		for e := range w.encrypted {
			buffer := <-e

			_, err := dest.Write(buffer)
			if err != nil {
				// FIXME: Deal with this error somehow.
				// Send them on the done channel.
				panic(err)
			}
			w.reBuf <- buffer
		}
		close(w.done)
	}()

	var wg sync.WaitGroup
	wg.Add(concurrent)

	for i := 0; i < concurrent; i++ {
		go func() {
			for j := range w.todo {
				if j.last {
					setLastChunkFlag(&j.nonce)
				}
				out := w.a.Seal(j.in[:0], j.nonce[:], j.in, nil)
				j.out <- out
				w.reJob <- j
			}
			wg.Done()
		}()
	}

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
			j := <-w.reJob
			j.last = false
			j.in = w.inbuffer[:ChunkSize]

			copy(j.nonce[:], w.nonce[:])
			incNonce(&w.nonce)

			w.todo <- j
			w.encrypted <- j.out

			w.fill = 0
			w.inbuffer = <-w.reBuf
		}
		n := copy(w.inbuffer[w.fill:ChunkSize], p)
		w.fill += n
		p = p[n:]
	}

	return total, nil
}

func (w *Writer) Close() error {
	j := <-w.reJob
	j.last = true
	j.in = w.inbuffer[:w.fill]
	copy(j.nonce[:], w.nonce[:])

	w.todo <- j
	w.encrypted <- j.out
	w.inbuffer = <-w.reBuf

	close(w.todo)
	return <-w.done
}
