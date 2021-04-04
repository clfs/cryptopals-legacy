package cryptopals

import (
	"bytes"
	"math"
	"strings"
	"testing"
)

func TestChallenge9(t *testing.T) {
	t.Parallel()
	var (
		blockSize = 20
		in        = []byte("YELLOW SUBMARINE")
		want      = []byte("YELLOW SUBMARINE\x04\x04\x04\x04")
	)

	got := PKCS7Pad(in, blockSize)
	if !bytes.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestPKCS7Unpad(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		bs        int
		msg, pMsg []byte
	}{
		"challenge 9": {
			bs:   20,
			msg:  []byte("YELLOW SUBMARINE"),
			pMsg: []byte("YELLOW SUBMARINE\x04\x04\x04\x04"),
		},
		"extra block": {
			bs:   5,
			msg:  []byte("01234"),
			pMsg: []byte("01234\x05\x05\x05\x05\x05"),
		},
	}

	for name, tc := range cases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := PKCS7Pad(tc.msg, tc.bs)
			if !bytes.Equal(got, tc.pMsg) {
				t.Errorf("got %q, want pMsg %q", got, tc.pMsg)
			}

			got = PKCS7Unpad(got)
			if !bytes.Equal(got, tc.msg) {
				t.Errorf("got %q, want msg %q", got, tc.msg)
			}
		})
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

	ct1 := ecb.Encrypt(pt)
	ct2 := ecb.Encrypt(pt)
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
	want := HelperDecodeBase64(t, "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")

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

func TestProfileFor_NoMetacharacters(t *testing.T) {
	t.Parallel()

	cases := []string{
		"a&a",
		"b=b",
		"c=&c",
		"=",
		"&",
		"&&&===",
	}

	for i, email := range cases {
		got := ProfileFor(email)
		if strings.Count(got, "&") != 2 || strings.Count(got, "=") != 3 {
			t.Errorf("%d: unescaped metacharacters: %s", i, got)
		}
	}
}

func TestChallenge13(t *testing.T) {
	m, err := NewECBProfileManager()
	if err != nil {
		t.Error(err)
	}

	profile := NewAdminProfile(m)
	if !m.IsAdmin(profile) {
		t.Errorf("not admin profile: %x", profile)
	}
}
