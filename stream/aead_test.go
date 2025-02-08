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
