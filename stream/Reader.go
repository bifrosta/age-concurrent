package stream

import (
	"crypto/cipher"
	"errors"
	"io"
	"runtime"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

type Reader struct {
	reader io.Reader
}

func nonceIsZero(nonce *[chacha20poly1305.NonceSize]byte) bool {
	return *nonce == [chacha20poly1305.NonceSize]byte{}
}

func NewReader(a cipher.AEAD, src io.Reader, concurrent int) *Reader {
	if concurrent < 1 {
		concurrent = runtime.NumCPU()
	}

	reader, writer := io.Pipe()

	var nonce [chacha20poly1305.NonceSize]byte

	todo := make(chan *job, concurrent)
	decrypted := make(chan chan []byte, concurrent)
	done := make(chan error, 1)

	// Reusable output buffer, one extra for an active job
	// Another that is being written
	reBuf := make(chan []byte, concurrent+2)
	// Reusable jobs.
	// Add one extra so a job can be prepared while 'concurrent' are being decoded.
	reJob := make(chan *job, concurrent+1)
	for i := 0; i < concurrent+1; i++ {
		reBuf <- make([]byte, encChunkSize)
		reJob <- &job{out: make(chan []byte, 1), in: make([]byte, encChunkSize)}
	}
	reBuf <- make([]byte, encChunkSize)

	r := &Reader{
		reader: reader,
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer func() {
			close(todo)
			wg.Done()
		}()

		var err error
		var n int

		last := false

		for !last {
			j := <-reJob
			buffer := j.in[:encChunkSize]
			n, err = io.ReadFull(src, buffer)
			switch {
			case err == io.EOF:
				return
			case err == io.ErrUnexpectedEOF:
				// The last chunk can be short, but not empty unless it's the first and
				// only chunk.
				if !nonceIsZero(&nonce) && n == a.Overhead() {
					writer.CloseWithError(errors.New("last chunk is empty, try age v1.0.0, and please consider reporting this"))

					return
				}

				buffer = buffer[:n]
				last = true
				setLastChunkFlag(&nonce)

			case err != nil:
				writer.CloseWithError(err)

				return
			}

			j.in = buffer[:n]
			j.last = last
			j.nonce = nonce

			todo <- j
			decrypted <- j.out

			incNonce(&nonce)
		}
	}()

	wg.Add(concurrent)

	for i := 0; i < concurrent; i++ {
		go func() {
			defer wg.Done()
			// Track if we have seen a last nonce
			hasSeenLast := false
			for j := range todo {
				if hasSeenLast && len(j.in) > 0 {
					writer.CloseWithError(errors.New("unexpected data after last block"))
					return
				}
				if j.last {
					setLastChunkFlag(&j.nonce)
					hasSeenLast = true
				}
				dst := <-reBuf

				plaintext, err := a.Open(dst[:0], j.nonce[:], j.in, nil)
				if err != nil {
					if !j.last {
						// Check if this was a full-length final chunk.
						hasSeenLast = true
						setLastChunkFlag(&j.nonce)
						plaintext, err = a.Open(dst[:0], j.nonce[:], j.in, nil)
					}

					if err != nil {
						writer.CloseWithError(errors.New("failed to decrypt and authenticate payload chunk"))

						return
					}
				}
				j.out <- plaintext
				reJob <- j
			}
		}()
	}

	go func() {
		for d := range decrypted {
			buffer := <-d

			// TODO: Handle write errors
			_, _ = writer.Write(buffer)
			reBuf <- buffer
		}

		done <- writer.Close()
	}()

	go func() {
		wg.Wait()
		close(decrypted)
	}()

	return r
}

func (r *Reader) Read(p []byte) (int, error) {
	return r.reader.Read(p)
}
