package stream

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"testing"

	realage "filippo.io/age"
)

func BenchmarkReader(b *testing.B) {
	in := make([]byte, 1024*1024*11+555)
	_, _ = rand.Read(in)

	ident, err := realage.GenerateX25519Identity()
	if err != nil {
		b.Fatal(err)
	}

	testFile := bytes.NewBuffer(nil)

	w, err := realage.Encrypt(testFile, ident.Recipient())
	if err != nil {
		b.Fatal(err)
	}

	_, err = w.Write(in)
	if err != nil {
		b.Fatal(err)
	}

	err = w.Close()
	if err != nil {
		b.Fatal(err)
	}

	b.SetBytes(int64(len(testFile.Bytes())))
	b.ResetTimer()

	// Extract the payload from the real age to make benchmarking easier.
	payloadR, err := realage.Decrypt(bytes.NewBuffer(testFile.Bytes()), ident)
	if err != nil {
		b.Fatal(err)
	}

	a := Extract[cipher.AEAD](payloadR, "a")
	src := Extract[io.Reader](payloadR, "src")

	payload, err := io.ReadAll(src)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("realage", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(payload)))

		for i := 0; i < b.N; i++ {
			b.StopTimer()

			real, err := realage.Decrypt(bytes.NewBuffer(testFile.Bytes()), ident)
			if err != nil {
				b.Fatal(err)
			}

			b.StartTimer()

			_, _ = io.Copy(io.Discard, real)
		}
	})
	type wrapReader struct {
		io.Reader
	}

	for cpu := 1; cpu <= 32; cpu *= 2 {
		b.Run(fmt.Sprintf("cpu:%d", cpu), func(b *testing.B) {

			b.Run("read", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(payload)))
				for i := 0; i < b.N; i++ {
					dec := NewReader(a, bytes.NewReader(payload), cpu)

					_, _ = io.Copy(io.Discard, wrapReader{dec})
				}
			})
			b.Run("writeto", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(payload)))
				for i := 0; i < b.N; i++ {
					dec := NewReader(a, bytes.NewReader(payload), cpu)
					dec.WriteTo(io.Discard)
				}
			})
		})
	}
}
