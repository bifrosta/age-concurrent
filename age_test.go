package age

import (
	"bytes"
	"fmt"
	"io"
	"runtime"
	"testing"

	realage "filippo.io/age"
)

var (
	privateKey = "AGE-SECRET-KEY-1H305TP42AFYLAPZFEJRJ04GG6JWHG75YV5WDE6HGCQMJVKV8FNGS5SL8E4"
	publicKey1 = "age1hrdj44jclzr8r9dkekvl30mgz9zj58fzyfyu67phtfma5czps5tqzm9yzg"
	publicKey2 = "age1c8wcgj53sqc4lmpae30t68pdlktp5ey4yvgqxh87s9ng35j5wq8sy868xu"

	ident = func() realage.Identity {
		idents, _ := realage.ParseIdentities(bytes.NewReader([]byte(privateKey)))

		return idents[0]
	}()

	recipient1 = func() realage.Recipient {
		recipients, _ := realage.ParseRecipients(bytes.NewReader([]byte(publicKey1)))

		return recipients[0]
	}()

	recipient2 = func() realage.Recipient {
		recipients, _ := realage.ParseRecipients(bytes.NewReader([]byte(publicKey2)))

		return recipients[0]
	}()
)

func genString(length int) string {
	buf := make([]byte, length)

	for i := 0; i < length; i++ {
		buf[i] = byte(i)
	}

	return string(buf)
}

func TestEncryptNoRecipient(t *testing.T) {
	buf := bytes.NewBuffer(nil)

	_, err := Encrypt(buf)
	if err == nil {
		t.Errorf("expected error, got nil")
	}
}

func TestDecryptNoIdentity(t *testing.T) {
	buf := bytes.NewBuffer(nil)

	_, err := Decrypt(buf)
	if err == nil {
		t.Errorf("expected error, got nil")
	}
}

func encryptReader(r io.Reader, recipients ...realage.Recipient) (io.Reader, error) {
	buf := bytes.NewBuffer(nil)

	w, err := Encrypt(buf, recipients...)
	if err != nil {
		return nil, err
	}

	_, err = io.Copy(w, r)
	if err != nil {
		return nil, err
	}

	err = w.Close()
	if err != nil {
		return nil, err
	}

	return buf, nil
}

var cases = []string{
	"",
	"hello",
	genString(1024),
	genString(64*1024 - 5),
	genString(64*1024 - 4),
	genString(64*1024 - 3),
	genString(64*1024 - 2),
	genString(64*1024 - 1),
	genString(64 * 1024),
	genString(64*1024 + 1),
	genString(64*1024 + 2),
	genString(64*1024 + 3),
	genString(64*1024 + 4),
	genString(2*64*1024 - 5),
	genString(2*64*1024 - 4),
	genString(2*64*1024 - 3),
	genString(2*64*1024 - 2),
	genString(2*64*1024 - 1),
	genString(2*64*1024 + 0),
	genString(2*64*1024 + 1),
	genString(2*64*1024 + 2),
	genString(2*64*1024 + 3),
	genString(2*64*1024 + 4),
	genString(runtime.NumCPU()*64*1024 - 5),
	genString(runtime.NumCPU()*64*1024 - 4),
	genString(runtime.NumCPU()*64*1024 - 3),
	genString(runtime.NumCPU()*64*1024 - 2),
	genString(runtime.NumCPU()*64*1024 - 1),
	genString(runtime.NumCPU()*64*1024 + 0),
	genString(runtime.NumCPU()*64*1024 + 1),
	genString(runtime.NumCPU()*64*1024 + 2),
	genString(runtime.NumCPU()*64*1024 + 3),
	genString(runtime.NumCPU()*64*1024 + 4),
	genString((runtime.NumCPU()+1)*64*1024 - 5),
	genString((runtime.NumCPU()+1)*64*1024 - 4),
	genString((runtime.NumCPU()+1)*64*1024 - 3),
	genString((runtime.NumCPU()+1)*64*1024 - 2),
	genString((runtime.NumCPU()+1)*64*1024 - 1),
	genString((runtime.NumCPU()+1)*64*1024 + 0),
	genString((runtime.NumCPU()+1)*64*1024 + 1),
	genString((runtime.NumCPU()+1)*64*1024 + 2),
	genString((runtime.NumCPU()+1)*64*1024 + 3),
	genString((runtime.NumCPU()+1)*64*1024 + 4),
	genString(1 * 64 * 1024),
	genString(2 * 64 * 1024),
	genString(3 * 64 * 1024),
	genString(4 * 64 * 1024),
	genString(5 * 64 * 1024),
	genString(6 * 64 * 1024),
	genString(7 * 64 * 1024),
	genString(8 * 64 * 1024),
	genString(9 * 64 * 1024),
	genString(10 * 64 * 1024),
	genString(11 * 64 * 1024),
	genString(12 * 64 * 1024),
	genString(13 * 64 * 1024),
	genString(14 * 64 * 1024),
	genString(15 * 64 * 1024),
	genString(16 * 64 * 1024),
	genString(17 * 64 * 1024),
	genString(18 * 64 * 1024),
	genString(19 * 64 * 1024),
	genString(20 * 64 * 1024),
	genString(21 * 64 * 1024),
	genString(22 * 64 * 1024),
	genString(23 * 64 * 1024),
	genString(24 * 64 * 1024),
	genString(25 * 64 * 1024),
	genString(26 * 64 * 1024),
	genString(27 * 64 * 1024),
	genString(28 * 64 * 1024),
	genString(29 * 64 * 1024),
	genString(30 * 64 * 1024),
	genString(31 * 64 * 1024),
	genString(32 * 64 * 1024),
	genString(33 * 64 * 1024),
	genString(34 * 64 * 1024),
	genString(35 * 64 * 1024),
	genString(36 * 64 * 1024),
	genString(37 * 64 * 1024),
	genString(38 * 64 * 1024),
	genString(39 * 64 * 1024),
	genString(40 * 64 * 1024),
	genString(1024 * 1024),
	genString(5 * 1024 * 1024),
}

func TestDecrypt(t *testing.T) {
	for _, c := range cases {
		t.Run(fmt.Sprintf("%d", len(c)), func(t *testing.T) {
			encrypted := bytes.NewBuffer(nil)
			w, err := Encrypt(encrypted, recipient1)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			_, err = w.Write([]byte(c))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			err = w.Close()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			encryptedReader := bytes.NewReader(encrypted.Bytes())

			r, err := Decrypt(encryptedReader, ident)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			out := bytes.NewBuffer(nil)

			n, err := io.Copy(out, r)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(c) != int(n) {
				t.Fatalf("unexpected length: %d", n)
			}

			if !bytes.Equal(out.Bytes(), []byte(c)) {
				t.Fatalf("unexpected output")
			}
		})
	}
}

func TestEncrypt(t *testing.T) {
	for _, c := range cases {
		t.Run(fmt.Sprintf("%d", len(c)), func(t *testing.T) {
			test := []byte(c)

			buf := bytes.NewBuffer(nil)

			w, err := Encrypt(buf, recipient1)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			_, err = w.Write(test)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			err = w.Close()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			r, err := realage.Decrypt(buf, ident)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			out := bytes.NewBuffer(nil)

			_, err = out.ReadFrom(r)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if !bytes.Equal(out.Bytes(), test) {
				t.Errorf("unexpected output: %q", out.Bytes())
			}

			buf.Reset()

			w, err = Encrypt(buf, recipient2)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			_, err = w.Write(test)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			err = w.Close()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			r, err = realage.Decrypt(buf, ident)
			if err == nil {
				t.Errorf("expected error, got nil")
			}

			if r != nil {
				t.Errorf("unexpected reader: %v", r)
			}
		})
	}
}
