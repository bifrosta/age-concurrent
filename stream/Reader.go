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

	r := &Reader{
		reader: reader,
	}

	go func() {
		defer func() { close(todo) }()

		var err error
		var n int

		last := false

		for !last {
			buffer := make([]byte, encChunkSize)
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

			j := &job{
				in:   buffer[:n],
				last: last,
				out:  make(chan []byte, 1),
			}

			copy(j.nonce[:], nonce[:])

			todo <- j
			decrypted <- j.out

			incNonce(&nonce)
		}
	}()

	var wg sync.WaitGroup

	wg.Add(concurrent)

	for i := 0; i < concurrent; i++ {
		go func() {
			defer wg.Done()

			for j := range todo {
				if j.last {
					setLastChunkFlag(&j.nonce)
				}

				plaintext, err := a.Open(j.in[:0], j.nonce[:], j.in, nil)
				if err != nil {
					if !j.last {
						// Check if this was a full-length final chunk.
						j.last = true
						setLastChunkFlag(&j.nonce)
						plaintext, err = a.Open(j.in[:0], j.nonce[:], j.in, nil)
					}

					if err != nil {
						writer.CloseWithError(errors.New("failed to decrypt and authenticate payload chunk"))

						return
					}
				}

				j.out <- plaintext
			}
		}()
	}

	go func() {
		for d := range decrypted {
			buffer := <-d

			_, _ = writer.Write(buffer)
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
