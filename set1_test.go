package cryptopals

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"testing"
)

// HelperHexDecode returns s decoded from hex.
func HelperHexDecode(tb testing.TB, s string) []byte {
	tb.Helper()
	h, err := hex.DecodeString(s)
	if err != nil {
		tb.Fatalf("could not decode %s: %v", s, err)
	}
	return h
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

func TestHexToBase64(t *testing.T) {
	t.Parallel()
	var (
		s    = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
		want = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	)

	got, err := HexToBase64(s)
	if err != nil {
		t.Error(err)
	}
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestXORBytes(t *testing.T) {
	t.Parallel()
	var (
		a    = HelperHexDecode(t, "1c0111001f010100061a024b53535009181c")
		b    = HelperHexDecode(t, "686974207468652062756c6c277320657965")
		want = HelperHexDecode(t, "746865206b696420646f6e277420706c6179")
	)

	got, err := XORBytes(a, b)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got %x, want %x", got, want)
	}
}

func TestSingleXORFindKey(t *testing.T) {
	t.Parallel()
	var (
		ct        = HelperHexDecode(t, "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
		want byte = 88
	)

	got, err := SingleXORFindKey(ct)
	if err != nil {
		t.Error(err)
	}
	if got != want {
		t.Errorf("got %d, want %d", got, want)
	}

	t.Logf("solve: %s", XORByte(ct, got))
}

func TestDetectSingleXOR(t *testing.T) {
	t.Parallel()
	var (
		data = HelperReadFile(t, "testdata/4.txt")
		want = HelperHexDecode(t, "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f")
	)

	cts := make([][]byte, 0)
	for _, h := range bytes.Split(data, []byte("\n")) {
		cts = append(cts, HelperHexDecode(t, string(h)))
	}

	got, err := SingleXORDetect(cts)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got %x, want %x", got, want)
	}
	pt, err := SingleXORFindPT(got)
	if err != nil {
		t.Error(err)
	}

	t.Logf("solve: %s", pt)
}

func TestRepeatingXOR(t *testing.T) {
	t.Parallel()
	var (
		pt   = []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
		key  = []byte("ICE")
		want = HelperHexDecode(t, "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
	)

	got := RepeatingXOR(pt, key)
	if !bytes.Equal(got, want) {
		t.Errorf("got %x, want %x", got, want)
	}
}

func TestHamming(t *testing.T) {
	t.Parallel()
	var (
		a    = []byte("this is a test")
		b    = []byte("wokka wokka!!!")
		want = 37
	)

	got, err := Hamming(a, b)
	if err != nil {
		t.Error(err)
	}
	if got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestRepeatingXORFindKey(t *testing.T) {
	t.Parallel()
	var (
		ct   = HelperReadFileBase64(t, "testdata/6.txt")
		want = HelperHexDecode(t, "5465726d696e61746f7220583a204272696e6720746865206e6f697365")
	)

	got, err := RepeatingXORFindKey(ct)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got %x, want %x", got, want)
	}

	t.Logf("solve: %s", RepeatingXOR(ct, got))
}
