package main

import "testing"

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
