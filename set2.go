package cryptopals

import (
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
