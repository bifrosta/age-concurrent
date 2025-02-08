package stream

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestAead(t *testing.T) {
	a, err := chacha20poly1305.New([]byte("key1key1key1key1key1key1key1key1"))
	if err != nil {
		t.Fatal(err)
	}

	nonce := [chacha20poly1305.NonceSize]byte{}

	incNonce(&nonce)

	in := make([]byte, ChunkSize)
	in[510] = 0x55
	in[511] = 0x55

	sealed := a.Seal(nil, nonce[:], in, nil)

	if len(sealed) != encChunkSize {
		t.Errorf("unexpected len of sealed data: %d", len(sealed))
	}

	plain, err := a.Open(nil, nonce[:], sealed, nil)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(in, plain) {
		t.Errorf("unexpected: %q", plain)
	}
}

func TestAeadFail(t *testing.T) {
	a1, err := chacha20poly1305.New([]byte("key1key1key1key1key1key1key1key1"))
	if err != nil {
		t.Fatal(err)
	}

	a2, err := chacha20poly1305.New([]byte("key2key2key2key2key2key2key2key2"))
	if err != nil {
		t.Fatal(err)
	}

	nonce := [chacha20poly1305.NonceSize]byte{}

	sealed := a1.Seal(nil, nonce[:], []byte("hellohellohellohellohellohello"), nil)

	_, err = a2.Open(nil, nonce[:], sealed, nil)
	if err == nil {
		t.Error("unexpected success")
	}
}

func BenchmarkAeadOpen(b *testing.B) {
	const opens = 100

	a, err := chacha20poly1305.New([]byte("key1key1key1key1key1key1key1key1"))
	if err != nil {
		b.Fatal(err)
	}

	nonce := make([]byte, chacha20poly1305.NonceSize)

	in := make([]byte, ChunkSize)

	sealed := a.Seal(nil, nonce, in, nil)

	b.SetBytes(int64(len(sealed) * opens))
	b.ReportAllocs()

	out := make([]byte, ChunkSize)

	for i := 0; i < b.N; i++ {
		for j := 0; j < opens; j++ {
			_, err := a.Open(out[:0], nonce, sealed, nil)
			if err != nil {
				b.Fatal(err)
			}
		}
	}
}

func BenchmarkAeadSeal(b *testing.B) {
	const seals = 100

	a, err := chacha20poly1305.New([]byte("key1key1key1key1key1key1key1key1"))
	if err != nil {
		b.Fatal(err)
	}

	nonce := make([]byte, chacha20poly1305.NonceSize)

	in := make([]byte, ChunkSize)

	b.SetBytes(int64(len(in) * seals))
	b.ReportAllocs()

	out := make([]byte, encChunkSize)

	for i := 0; i < b.N; i++ {
		for j := 0; j < seals; j++ {
			_ = a.Seal(out[:0], nonce, in, nil)
		}
	}
}
