package age

import (
	"crypto/cipher"
	"io"

	realage "filippo.io/age"

	"github.com/bifrosta/age-concurrent/stream"
)

// Verify that the function signatures match the real age package.
var (
	_ func(io.Writer, ...realage.Recipient) (io.WriteCloser, error) = Encrypt
	_ func(io.Writer, ...Recipient) (io.WriteCloser, error)         = realage.Encrypt
	_ func(io.Reader, ...realage.Identity) (io.Reader, error)       = Decrypt
	_ func(io.Reader, ...Identity) (io.Reader, error)               = realage.Decrypt
)

// Encrypt encrypts a file to one or more recipients.
//
// Writes to the returned WriteCloser are encrypted and written to dst as an age
// file. Every recipient will be able to decrypt the file.
//
// The caller must call Close on the WriteCloser when done for the last chunk to
// be encrypted and flushed to dst.
func Encrypt(dst io.Writer, recipients ...Recipient) (io.WriteCloser, error) {
	w, err := realage.Encrypt(dst, recipients...)
	if err != nil {
		return nil, err
	}

	a := stream.Extract[cipher.AEAD](w, "a")

	return stream.NewWriter(a, dst, 0), nil
}

// Decrypt decrypts a file encrypted to one or more identities.
//
// It returns a Reader reading the decrypted plaintext of the age file read
// from src. All identities will be tried until one successfully decrypts the file.
func Decrypt(src io.Reader, identities ...Identity) (io.Reader, error) {
	r, err := realage.Decrypt(src, identities...)
	if err != nil {
		return nil, err
	}

	a := stream.Extract[cipher.AEAD](r, "a")
	src = stream.Extract[io.Reader](r, "src")

	return stream.NewReader(a, src, 0), nil
}
