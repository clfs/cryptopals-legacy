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
