package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"math"
)

// PKCS7Pad pads a byte slice using PKCS#7.
func PKCS7Pad(b []byte, blockSize int) ([]byte, error) {
	if blockSize > math.MaxUint8 {
		return nil, fmt.Errorf("invalid block size %d", blockSize)
	}

	var (
		pad = blockSize - len(b)%blockSize
		res = make([]byte, len(b)+pad)
	)

	copy(res, b)
	for i := len(b); i < len(res); i++ {
		res[i] = byte(pad)
	}
	return res, nil
}

// CBCCipher represents a CBC mode cipher.
type CBCCipher struct {
	b cipher.Block
}

// NewCBCCipher returns a new CBCCipher.
func NewCBCCipher(key []byte) (*CBCCipher, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &CBCCipher{b: b}, nil
}

// Encrypt encrypts a plaintext using an IV.
func (c *CBCCipher) Encrypt(pt, iv []byte) ([]byte, error) {
	if len(pt)%c.b.BlockSize() != 0 {
		return nil, fmt.Errorf("invalid plaintext")
	}
	if len(iv) != c.b.BlockSize() {
		return nil, fmt.Errorf("invalid IV")
	}

	var (
		ct   = make([]byte, len(pt))
		prev = iv
	)

	for i := 0; i < len(pt); i += c.b.BlockSize() {
		tmp, err := XORBytes(pt[i:i+c.b.BlockSize()], prev)
		if err != nil {
			return nil, err
		}
		copy(ct[i:], tmp)
		c.b.Encrypt(ct[i:], ct[i:])
		prev = ct[i : i+c.b.BlockSize()]
	}

	return ct, nil
}

// Decrypt decrypts a ciphertext using an IV.
func (c *CBCCipher) Decrypt(ct, iv []byte) ([]byte, error) {
	if len(ct)%c.b.BlockSize() != 0 {
		return nil, fmt.Errorf("invalid ciphertext")
	}
	if len(iv) != c.b.BlockSize() {
		return nil, fmt.Errorf("invalid IV")
	}

	var (
		pt   = make([]byte, len(ct))
		tmp  = make([]byte, c.b.BlockSize())
		prev = iv
	)

	for i := 0; i < len(ct); i += c.b.BlockSize() {
		c.b.Decrypt(tmp, ct[i:])
		tmp, err := XORBytes(tmp, prev)
		if err != nil {
			return nil, err
		}
		copy(pt[i:], tmp)
		prev = ct[i : i+c.b.BlockSize()]
	}

	return pt, nil
}

// ECBOrCBCOracle represents an ECB or CBC mode encryption oracle.
type ECBOrCBCOracle struct {
	ecb *ECBCipher
	cbc *CBCCipher
}

// NewECBOrCBCOracle returns a new ECBOrCBCOracle
func NewECBOrCBCOracle() (*ECBOrCBCOracle, error) {
	key := make([]byte, 16)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}

	ecb, err := NewECBCipher(key)
	if err != nil {
		return nil, err
	}

	cbc, err := NewCBCCipher(key)
	if err != nil {
		return nil, err
	}

	return &ECBOrCBCOracle{ecb: ecb, cbc: cbc}, nil
}

// Encrypt encrypts a plaintext under ECB or CBC mode, with a
// 50/50 chance of either. Random data is both prepended and
// appended to the plaintext before encryption. If CBC is
// chosen, a random IV is used.
func (e *ECBOrCBCOracle) Encrypt(pt []byte) ([]byte, error) {
	prefixLen, err := rand.Int(rand.Reader, big6) // [0, 6)
	if err != nil {
		return nil, err
	}
	suffixLen, err := rand.Int(rand.Reader, big6) // [0, 6)
	if err != nil {
		return nil, err
	}
	prefixLen.Add(prefixLen, big5) // [5, 10]
	suffixLen.Add(suffixLen, big5) // [5, 10]

	if RandBool() { // ECB
		return e.ecb.Encrypt(pt)
	}

	// Otherwise, CBC.
	iv := make([]byte, 16)
	_, err = rand.Read(iv)
	if err != nil {
		return nil, err
	}
	return e.cbc.Encrypt(pt, iv)
}

// RandBool returns a cryptographically random bool.
// It panics on failure.
func RandBool() bool {
	n, err := rand.Int(rand.Reader, big2) // [0, 2)
	if err != nil {
		panic("should never happen")
	}
	return n.Bit(0) == 0
}

type ECBAppendOracle struct {
	ecb    *ECBCipher
	suffix []byte
}

func NewECBAppendOracle(suffix []byte) (*ECBAppendOracle, error) {
	key := make([]byte, 16)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}

	ecb, err := NewECBCipher(key)
	if err != nil {
		return nil, err
	}

	return &ECBAppendOracle{ecb: ecb, suffix: suffix}, nil
}

func (e ECBAppendOracle) Encrypt(b []byte) ([]byte, error) {
	pt, err := PKCS7Pad(append(b, e.suffix...), 16)
	if err != nil {
		return nil, err
	}

	ct, err := e.ecb.Encrypt(pt)
	if err != nil {
		return nil, err
	}

	return ct, nil
}

func ECBAppendFindBlockSize(oracle *ECBAppendOracle) (int, error) {
	for bs := 2; bs <= 128; bs++ {
		pt := bytes.Repeat([]byte{0}, bs*2)

		ct, err := oracle.Encrypt(pt)
		if err != nil {
			return 0, err
		}

		if IsECB(ct, bs) {
			return bs, nil
		}
	}
	return 0, fmt.Errorf("block size not found")
}

func ECBAppendFindSuffixLen(oracle *ECBAppendOracle) (int, error) {
	bs, err := ECBAppendFindBlockSize(oracle)
	if err != nil {
		return 0, err
	}

	ct, err := oracle.Encrypt([]byte{})
	if err != nil {
		return 0, err
	}

	bound := len(ct)

	for i := 1; i <= bs; i++ {
		pt := bytes.Repeat([]byte{0}, i)

		ct, err := oracle.Encrypt(pt)
		if err != nil {
			return 0, err
		}

		if len(ct) > bound {
			return bound - i, nil
		}
	}

	return 0, fmt.Errorf("suffix length not found")
}

func ECBAppendRecoverSuffix(oracle *ECBAppendOracle) ([]byte, error) {
	bs, err := ECBAppendFindBlockSize(oracle)
	if err != nil {
		return nil, err
	}

	suffixLen, err := ECBAppendFindSuffixLen(oracle)
	if err != nil {
		return nil, err
	}

	var res []byte

	for i := 0; i < suffixLen; i++ {
		referencePT := bytes.Repeat([]byte{0}, bs-(len(res)%bs)-1)
		referenceCT, err := oracle.Encrypt(referencePT)
		if err != nil {
			return nil, err
		}

		for j := 0; j < 256; j++ {
			pt := append(append(referencePT, res...), byte(j))
			ct, err := oracle.Encrypt(pt)
			if err != nil {
				return nil, err
			}

			if bytes.Equal(ct[:len(pt)], referenceCT[:len(pt)]) {
				res = append(res, byte(j))
				break
			}
		}
	}

	return res, nil
}
