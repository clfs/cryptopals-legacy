package cryptopals

import (
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"math/bits"
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

// SingleXORFindKey recovers the key from a single-byte-XOR
// encrypted ciphertext.
func SingleXORFindKey(ct []byte) (byte, error) {
	if len(ct) == 0 {
		return 0, fmt.Errorf("empty ciphertext")
	}

	var (
		bestScore = -math.MaxFloat64 // higher is better
		bestK     int
	)

	for k := 0; k < 256; k++ {
		pt := XORByte(ct, byte(k))
		score := Englishness(pt)
		if score > bestScore {
			bestScore = score
			bestK = k
		}
	}

	return byte(bestK), nil
}

// Englishness returns a score representing how English-like
// a text is. The score is between 0 and 1 inclusive. If
// b is empty, its score is 0.
func Englishness(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}

	var count int
	for _, v := range b {
		if v == ' ' || v == 'e' || v == 't' || v == 'a' {
			count++
		}
	}

	return float64(count) / float64(len(b))
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
		freq[v]++
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

// SingleXORFindPT attacks single-XOR encryption
// and returns a likely plaintext.
func SingleXORFindPT(ct []byte) ([]byte, error) {
	key, err := SingleXORFindKey(ct)
	if err != nil {
		return nil, err
	}
	return XORByte(ct, key), nil
}

// RepeatingXOR XORs b against a key. The key
// will repeat if it's too short.
func RepeatingXOR(b, key []byte) []byte {
	res := make([]byte, len(b))
	for i := range b {
		res[i] = b[i] ^ key[i%len(key)]
	}
	return res
}

// Hamming returns the number of bits that differ between
// a and b. It fails if their lengths are unequal.
func Hamming(a, b []byte) (int, error) {
	if len(a) != len(b) {
		return 0, fmt.Errorf("unequal lengths")
	}

	var res int
	for i := range a {
		res += bits.OnesCount(uint(a[i] ^ b[i]))
	}
	return res, nil
}

// RepeatingXORFindKey attacks repeating-XOR encryption
// and returns a likely key.
func RepeatingXORFindKey(ct []byte) ([]byte, error) {
	keySize, err := RepeatingXORFindKeySize(ct, 2, 40)
	if err != nil {
		return nil, err
	}
	chunkSize := (len(ct) + keySize - 1) / keySize

	var (
		key   = make([]byte, keySize)
		chunk = make([]byte, chunkSize)
	)

	for i := range key {
		// Read the chunk.
		for j := range chunk {
			k := j*keySize + i
			if k < len(ct) {
				chunk[j] = ct[k]
			}
		}

		// Find one byte of key material.
		key[i], err = SingleXORFindKey(chunk)
		if err != nil {
			return nil, err
		}
	}

	return key, nil
}

// RepeatingXORFindKeySize attacks repeating-XOR encryption
// and returns a likely key size. It checks all key sizes between
// a and b, inclusive.
func RepeatingXORFindKeySize(ct []byte, a, b int) (int, error) {
	if a > b || 8*b > len(ct) {
		return 0, fmt.Errorf("invalid range")
	}

	var (
		bestSize  int
		bestScore = math.MaxFloat64
	)

	for n := a; n <= b; n++ {
		// Challenge 6 recommends taking multiple blocks.
		x, y := ct[:n*4], ct[n*4:n*8]
		h, err := Hamming(x, y)
		if err != nil {
			return 0, err
		}

		score := float64(h) / float64(n)
		if score < bestScore {
			bestSize = n
			bestScore = score
		}
	}

	return bestSize, nil
}

// ECBDecrypt decrypts an ECB ciphertext.
func ECBDecrypt(ct []byte, b cipher.Block) ([]byte, error) {
	if len(ct)%b.BlockSize() != 0 {
		return nil, fmt.Errorf("invalid ECB ciphertext")
	}
	pt := make([]byte, len(ct))
	for i := 0; i < len(pt); i += b.BlockSize() {
		b.Decrypt(pt[i:], ct[i:])
	}
	return pt, nil
}
