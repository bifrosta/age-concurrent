package stream

import (
	"crypto/cipher"
	"fmt"
	"io"
	"reflect"
	"testing"
	"unsafe"

	realage "filippo.io/age"
)

func BenchmarkWriter(b *testing.B) {
	const wrSize = 100000
	const writes = 1000
	const sz = wrSize * writes
	buf := make([]byte, wrSize)
	i, err := realage.GenerateX25519Identity()
	if err != nil {
		b.Fatal(err)
	}
	r := i.Recipient()
	w, err := realage.Encrypt(io.Discard, r)
	if err != nil {
		b.Fatal(err)
	}

	a := extractAEAD(w)

	b.Run("realage", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(sz))

		real, err := realage.Encrypt(io.Discard, r)
		if err != nil {
			b.Fatal(err)
		}

		for i := 0; i < b.N; i++ {
			for j := 0; j < writes; j++ {
				_, err = real.Write(buf)
				if err != nil {
					b.Fatal(err)
				}
			}
		}

		real.Close()
	})

	for cpu := 1; cpu <= 32; cpu *= 2 {
		b.Run(fmt.Sprintf("cpu:%d", cpu), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(sz))
			for i := 0; i < b.N; i++ {
				w2 := NewWriter(a, io.Discard, cpu)
				for j := 0; j < writes; j++ {
					w2.Write(buf)
				}
				w2.Close()
			}
		})
	}
}

// extractAEAD will extract the AEAD cipher from a
// filippo.io/age/internal/stream Writer or Reader.
// This is relatively safe, but tied to a specific
// version of the age module.
func extractAEAD(d any) cipher.AEAD {
	value := reflect.ValueOf(d)
	elem := value.Elem()

	field := elem.FieldByName("a")
	if field.IsZero() {
		panic("field 'a' not found")
	}

	aeadValue := reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr()))

	aead, ok := aeadValue.Interface().(*cipher.AEAD)
	if !ok {
		panic("field 'a' has unexpected type")
	}

	return *aead
}
