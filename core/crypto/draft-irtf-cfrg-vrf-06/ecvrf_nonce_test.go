package vrf

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

func hd(t *testing.T, s string) []byte {
	t.Helper()
	s = strings.ReplaceAll(s, " ", "")
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// test vector from https://tools.ietf.org/html/rfc6979#appendix-A.2.5
func TestGenerateNonceRFC6979(t *testing.T) {
	hash := crypto.SHA256
	SK := &PrivateKey{
		x: new(big.Int).SetBytes(hd(t, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721")),
		PublicKey: PublicKey{
			X:     new(big.Int).SetBytes(hd(t, "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6")),
			Y:     new(big.Int).SetBytes(hd(t, "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299")),
			Curve: elliptic.P256(),
		},
	}
	m := []byte("sample")

	if got, want := GenerateNonceRFC6979(hash, SK, m).Bytes(),
		hd(t, "A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60"); !bytes.Equal(got, want) {
		t.Errorf("k: %x, want %x", got, want)
	}
}
