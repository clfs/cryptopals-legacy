package cryptopals

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func HelperHexDecode(tb testing.TB, s string) []byte {
	tb.Helper()
	h, err := hex.DecodeString(s)
	if err != nil {
		tb.Errorf("error: %v", err)
	}
	return h
}

func TestHexToBase64(t *testing.T) {
	var (
		s    = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
		want = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	)
	got, err := HexToBase64(s)
	if err != nil {
		t.Errorf("error: %v", err)
	}
	if got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestXORBytes(t *testing.T) {
	var (
		a    = HelperHexDecode(t, "1c0111001f010100061a024b53535009181c")
		b    = HelperHexDecode(t, "686974207468652062756c6c277320657965")
		want = HelperHexDecode(t, "746865206b696420646f6e277420706c6179")
	)
	got, err := XORBytes(a, b)
	if err != nil {
		t.Errorf("error: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
