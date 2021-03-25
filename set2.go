package cryptopals

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"math"
)

func PKCS7Pad(b []byte, blockSize int) ([]byte, error) {
	if blockSize < len(b) || blockSize > math.MaxUint8 {
		return nil, fmt.Errorf("invalid block size")
	}

	var (
		pad = blockSize - len(b)%blockSize
		res = make([]byte, blockSize)
	)

	copy(res, b)
	for i := len(b); i < blockSize; i++ {
		res[i] = byte(pad)
	}
	return res, nil
}

type CBCCipher struct {
	b cipher.Block
}

func NewCBCCipher(key []byte) (*CBCCipher, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &CBCCipher{b: b}, nil
}

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

type ECBOrCBCCipher struct {
	ecb *ECBCipher
	cbc *CBCCipher
}

func NewECBOrCBCCipher() (*ECBOrCBCCipher, error) {
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

	return &ECBOrCBCCipher{ecb: ecb, cbc: cbc}, nil
}

func (e *ECBOrCBCCipher) Encrypt(pt []byte) ([]byte, error) {
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
		panic("lazy")
	}
	return n.Bit(0) == 0
}
