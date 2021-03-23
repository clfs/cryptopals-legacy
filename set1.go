package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// HexToBase64 converts hex strings to Base64 strings.
func HexToBase64(s string) (string, error) {
	h, err := hex.DecodeString(s)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(h), nil
}

// XORBytes XORs two byte slices. It fails if their lengths
// are unequal.
func XORBytes(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("unequal lengths")
	}
	res := make([]byte, len(a))
	for i := range a {
		res[i] = a[i] ^ b[i]
	}
	return res, nil
}

// XORByte XORs a byte slice with a single byte.
func XORByte(a []byte, b byte) []byte {
	res := make([]byte, len(a))
	for i := range a {
		res[i] = a[i] ^ b
	}
	return res
}

// SingleXORRecoverKey recovers the key from a single-byte-XOR
// encrypted ciphertext.
func SingleXORRecoverKey(ct []byte) (byte, error) {
	if len(ct) == 0 {
		return 0, fmt.Errorf("empty ciphertext")
	}

	freq := make(map[byte]int)
	for _, b := range ct {
		freq[b] += 1
	}

	var (
		mode byte
		best int
	)

	for b, count := range freq {
		if count > best {
			best = count
			mode = b
		}
	}

	// In Western languages, the most common byte
	// is usually an ASCII space.
	return mode ^ ' ', nil
}
