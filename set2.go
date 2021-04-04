package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"log"
	"math"
	"net/url"
)

// PKCS7Pad pads a byte slice using PKCS#7.
func PKCS7Pad(b []byte, blockSize int) []byte {
	if blockSize > math.MaxUint8 {
		panic(fmt.Sprintf("invalid block size %d", blockSize))
	}

	var (
		pad = blockSize - len(b)%blockSize
		res = make([]byte, len(b)+pad)
	)

	copy(res, b)
	for i := len(b); i < len(res); i++ {
		res[i] = byte(pad)
	}
	return res
}

// PKCS7Unpad unpads a byte slice using PKCS#7. It doesn't check any
// byte other than the last, so it's super insecure. That's not
// important for any attack; I'm just lazy.
// It panics on invalid input.
func PKCS7Unpad(b []byte) []byte {
	if len(b) == 0 {
		return b
	}

	pad := b[len(b)-1]
	if pad == 0 || int(pad) > len(b) {
		panic(fmt.Sprintf("invalid pad byte %x", pad))
	}

	return b[:len(b)-int(pad)]
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
		return e.ecb.Encrypt(pt), nil
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

func (e ECBAppendOracle) Encrypt(b []byte) []byte {
	pt := PKCS7Pad(append(b, e.suffix...), 16)
	return e.ecb.Encrypt(pt)
}

func ECBAppendFindBlockSize(oracle *ECBAppendOracle) (int, error) {
	for bs := 2; bs <= 128; bs++ {
		pt := bytes.Repeat([]byte{0}, bs*2)
		ct := oracle.Encrypt(pt)

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

	ct := oracle.Encrypt([]byte{})
	bound := len(ct)

	for i := 1; i <= bs; i++ {
		pt := bytes.Repeat([]byte{0}, i)
		ct := oracle.Encrypt(pt)

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
		referenceCT := oracle.Encrypt(referencePT)

		for j := 0; j < 256; j++ {
			pt := append(append(referencePT, res...), byte(j))
			ct := oracle.Encrypt(pt)

			if bytes.Equal(ct[:len(pt)], referenceCT[:len(pt)]) {
				res = append(res, byte(j))
				break
			}
		}
	}

	return res, nil
}

func ProfileFor(email string) string {
	v := url.Values{}
	v.Add("email", email)
	v.Add("uid", "10") // Random user ID lengths just make the attack more annoying.
	v.Add("role", "user")
	return v.Encode()
}

type ECBProfileManager struct {
	ecb *ECBCipher
}

func NewECBProfileManager() (*ECBProfileManager, error) {
	key := make([]byte, 16)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}

	ecb, err := NewECBCipher(key)
	if err != nil {
		return nil, err
	}

	return &ECBProfileManager{ecb: ecb}, nil
}

func (m ECBProfileManager) Profile(email string) string {
	profile := ProfileFor(email)
	log.Println(profile)
	pt := PKCS7Pad([]byte(profile), 16)
	return string(m.ecb.Encrypt(pt))
}

func (m ECBProfileManager) IsAdmin(profile string) bool {
	pt := m.ecb.Decrypt([]byte(profile))
	pt = PKCS7Unpad(pt)

	values, err := url.ParseQuery(string(pt))
	if err != nil {
		return false
	}
	return values.Get("role") == "admin"
}

// NewAdminProfile performs a cut-and-paste ECB attack to
// transform a user profile into an admin profile.
func NewAdminProfile(m *ECBProfileManager) string {
	// Note that url.Values sorts alphabetically by key.

	// |<------------>||<------------>|
	// email=jeffy.b%40amazon.com&role=user&uid=10.....
	b12 := m.Profile("jeffy.b@amazon.com")[:32]

	//                 |<------------>|
	// email=pizza%40x.admin&role=user&uid=10..........
	b3 := m.Profile("pizza@x.admin")[16:32]

	//                 |<------------>||<------------>|
	// email=y%40z.com&role=user&uid=10................
	b45 := m.Profile("y@z.com")[16:48]

	// |<------------>||<------------>||<------------>||<------------>||<------------>|
	// email=jeffy.b%40amazon.com&role=admin&role=user&role=user&uid=10................
	return b12 + b3 + b45
}
