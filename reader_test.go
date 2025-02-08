package age

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

type reader struct {
	source     []byte
	errorAfter int
	read       int
}

func newReader(source []byte, errorAfter int) *reader {
	return &reader{
		source:     source,
		errorAfter: errorAfter,
	}
}

func (r *reader) Read(p []byte) (n int, err error) {
	if len(p)+r.read >= r.errorAfter {
		n = copy(p, r.source[r.read:r.errorAfter])
		return n, errors.New("read error")
	}

	n = copy(p, r.source[r.read:])
	r.read += n

	return n, nil
}

func TestTestReader(t *testing.T) {
	cases := []struct {
		source     []byte
		errorAfter int
	}{
		{[]byte{1, 2, 3}, 0},
		{[]byte{1, 2, 3}, 1},
		{[]byte{1, 2, 3}, 2},
		{[]byte{1, 2, 3, 4}, 3},
		{[]byte{1, 2, 3, 4}, 4},
	}

	for _, c := range cases {
		t.Run(fmt.Sprintf("%d:%d", len(c.source), c.errorAfter), func(t *testing.T) {
			r := newReader(c.source, c.errorAfter)

			buf := make([]byte, len(c.source))

			n, err := r.Read(buf)
			if err == nil {
				t.Fatalf("expected error")
			}

			buf = buf[:n]

			if c.errorAfter != len(buf) {
				t.Fatalf("unexpected length: %d", len(buf))
			}

			if !bytes.Equal(buf, c.source[:c.errorAfter]) {
				t.Fatalf("unexpected output")
			}
		})
	}
}
