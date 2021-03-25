package cryptopals

import (
	"bytes"
	"testing"
)

func TestChallenge9(t *testing.T) {
	var (
		blockSize = 20
		in        = []byte("YELLOW SUBMARINE")
		want      = []byte("YELLOW SUBMARINE\x04\x04\x04\x04")
	)

	got, err := PKCS7Pad(in, blockSize)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCBCCipher(t *testing.T) {
	var (
		ct  = bytes.Repeat([]byte("\x01"), 16*100)
		key = bytes.Repeat([]byte("\x02"), 16)
		iv  = bytes.Repeat([]byte("\x03"), 16)
	)

	c, err := NewCBCCipher(key)
	if err != nil {
		t.Error(err)
	}
	pt, err := c.Decrypt(ct, iv)
	if err != nil {
		t.Error(err)
	}
	got, err := c.Encrypt(pt, iv)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(got, ct) {
		t.Errorf("got %x, want %x", got, ct)
	}
}

func TestChallenge10(t *testing.T) {
	var (
		ct  = HelperReadFileBase64(t, "testdata/10.txt")
		key = []byte("YELLOW SUBMARINE")
		iv  = bytes.Repeat([]byte("\x00"), 16)
	)

	c, err := NewCBCCipher(key)
	if err != nil {
		t.Error(err)
	}
	pt, err := c.Decrypt(ct, iv)
	if err != nil {
		t.Error(err)
	}

	t.Logf("solve: %s", pt)
}
