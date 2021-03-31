package cryptopals

import (
	"bytes"
	"math"
	"testing"
)

func TestChallenge9(t *testing.T) {
	t.Parallel()
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

func TestECBCipher(t *testing.T) {
	t.Parallel()
	var (
		pt  = bytes.Repeat([]byte{0}, 16*2)
		key = bytes.Repeat([]byte{0}, 16)
	)

	ecb, err := NewECBCipher(key)
	if err != nil {
		t.Error(err)
	}
	ct1, err := ecb.Encrypt(pt)
	if err != nil {
		t.Error(err)
	}
	ct2, err := ecb.Encrypt(pt)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(ct1, ct2) {
		t.Errorf("ct1 %x, ct2 %x", ct1, ct2)
	}
}

func TestCBCCipher(t *testing.T) {
	t.Parallel()
	var (
		ct  = bytes.Repeat([]byte{1}, 16*100)
		key = bytes.Repeat([]byte{2}, 16)
		iv  = bytes.Repeat([]byte{3}, 16)
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
	t.Parallel()
	var (
		ct  = HelperReadFileBase64(t, "testdata/10.txt")
		key = []byte("YELLOW SUBMARINE")
		iv  = bytes.Repeat([]byte{0}, 16)
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

func TestChallenge11(t *testing.T) {
	t.Parallel()
	var (
		pt     = bytes.Repeat([]byte{0}, 16*10)
		trials = 1000
	)

	oracle, err := NewECBOrCBCOracle()
	if err != nil {
		t.Error(err)
	}

	var ecb int
	for i := 0; i < trials; i++ {
		ct, err := oracle.Encrypt(pt)
		if err != nil {
			t.Error(err)
		}
		if IsECB(ct, 16) {
			ecb++
		}
	}

	freq := math.Abs(float64(ecb) / float64(trials))
	if freq < 0.4 || freq > 0.6 {
		t.Errorf("unusual freq: %f", freq)
	}
}

func TestChallenge12(t *testing.T) {
	t.Parallel()
	var want = HelperDecodeBase64(t, "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")

	oracle, err := NewECBAppendOracle(want)
	if err != nil {
		t.Error(err)
	}
	got, err := ECBAppendRecoverSuffix(oracle)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}

	t.Logf("solve: %s", got)
}
