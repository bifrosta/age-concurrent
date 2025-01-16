package age

import (
	"crypto/cipher"
	"reflect"
	"unsafe"
)

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
