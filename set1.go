package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
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

// Entropy calculates the entropy of a byte slice.
// Adapted from https://rosettacode.org/wiki/Entropy#Go
func Entropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}

	var (
		entropy float64
		freq    = make(map[byte]float64)
	)

	for _, v := range b {
		freq[v] += 1
	}

	for _, v := range freq {
		if v > 0 {
			entropy += -v * math.Log2(v/float64(len(b)))
		}
	}

	return entropy
}

// SingleXORDetect chooses a likely single-XOR-encrypted
// ciphertext from multiple ciphertexts. It selects
// the ciphertext with the lowest entropy.
func SingleXORDetect(cts [][]byte) ([]byte, error) {
	if len(cts) == 0 {
		return nil, fmt.Errorf("empty ciphertexts")
	}

	var (
		bestEntropy = math.MaxFloat64 // lower is better
		bestCT      []byte
	)

	for _, ct := range cts {
		e := Entropy(ct)
		if e < bestEntropy {
			bestEntropy = e
			bestCT = ct
		}
	}

	return bestCT, nil
}

// SingleXORBreak breaks single-XOR encryption
// and returns a likely plaintext.
func SingleXORBreak(ct []byte) ([]byte, error) {
	key, err := SingleXORRecoverKey(ct)
	if err != nil {
		return nil, err
	}
	return XORByte(ct, key), nil
}

func RepeatingXOR(b, key []byte) []byte {
	res := make([]byte, len(b))
	for i := range b {
		res[i] = b[i%len(key)]
	}
	return res
}
