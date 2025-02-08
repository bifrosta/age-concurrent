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

	a := extract[cipher.AEAD](w, "a")

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

// extract will extract a private field from a
// filippo.io/age/internal/stream Writer or Reader.
// This is relatively safe, but tied to a specific
// version of the age module.
func extract[T any](d any, field string) T {
	value := reflect.ValueOf(d)
	elem := value.Elem()

	fieldValue := elem.FieldByName(field)
	if fieldValue.IsZero() {
		panic(fmt.Sprintf("field '%s' not found", field))
	}

	fieldValuePtr := reflect.NewAt(fieldValue.Type(), unsafe.Pointer(fieldValue.UnsafeAddr()))

	fieldValueInterface, ok := fieldValuePtr.Interface().(*T)
	if !ok {
		panic(fmt.Sprintf("field '%s' has unexpected type", field))
	}

	return *fieldValueInterface
}
