package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"testing"
)

// HelperDecodeHex returns s decoded from hex.
func HelperDecodeHex(tb testing.TB, s string) []byte {
	tb.Helper()
	h, err := hex.DecodeString(s)
	if err != nil {
		tb.Fatalf("could not decode %s: %v", s, err)
	}
	return h
}

// HelperDecodeBase64 returns s decoded from Base64.
func HelperDecodeBase64(tb testing.TB, s string) []byte {
	tb.Helper()
	res, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		tb.Fatal(err)
	}
	return res
}

// HelperReadFile returns the contents of name.
func HelperReadFile(tb testing.TB, name string) []byte {
	tb.Helper()
	res, err := os.ReadFile(name)
	if err != nil {
		tb.Fatalf("could not read %s: %v", name, err)
	}
	return res
}

// HelperReadFileBase64 returns the decoded contents of name.
func HelperReadFileBase64(tb testing.TB, name string) []byte {
	tb.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		tb.Fatalf("could not read %s: %v", name, err)
	}
	res, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		tb.Fatalf("could not decode %s, %v", name, err)
	}
	return res
}
