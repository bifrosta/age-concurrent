package age

import (
	"errors"
	"fmt"
	"testing"
)

type writer struct {
	errorat int
	written int
}

func newWriter(errorat int) *writer {
	return &writer{
		errorat: errorat,
	}
}

func (w *writer) Write(p []byte) (n int, err error) {
	if w.errorat == 0 {
		return len(p), nil
	}

	if w.written+len(p) > w.errorat {
		n = w.errorat - w.written
		w.written += n
		return n, errors.New("write error")
	}

	w.written += len(p)

	return len(p), nil
}

func TestTestWriter(t *testing.T) {
	cases := []struct {
		errorat int
	}{
		{1},
		{2},
		{3},
		{4},
	}

	for _, c := range cases {
		t.Run(fmt.Sprintf("%d", c.errorat), func(t *testing.T) {
			w := newWriter(c.errorat)

			buf := []byte{1, 2, 3, 4, 5, 6, 7}

			n, err := w.Write(buf)
			if err == nil {
				t.Fatalf("expected error")
			}

			if c.errorat != n {
				t.Fatalf("unexpected length: %d", n)
			}
		})
	}
}
