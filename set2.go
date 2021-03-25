package cryptopals

import (
	"crypto/aes"
	"crypto/cipher"
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
