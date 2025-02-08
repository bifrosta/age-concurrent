package age

import (
	"fmt"
	"reflect"
	"unsafe"
)

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
