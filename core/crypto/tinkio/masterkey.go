package tinkio

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/google/tink/go/aead/subtle"
	"github.com/google/tink/go/tink"
	"golang.org/x/crypto/pbkdf2"
)

const (
	masterKeyLen        = 32
	masterKeyIterations = 4096
)

var (
	// openssl rand -hex 32
	salt, _           = hex.DecodeString("00afc05d5b131a1dfd140a146b87f2f07826a8d4576cb4feef43f80f0c9b1c2f")
	masterKeyHashFunc = sha256.New
)

// MasterPBKDF converts the master password into the master key.
func MasterPBKDF(masterPassword string) (tink.AEAD, error) {
	if masterPassword == "" {
		return nil, fmt.Errorf("please provide a master password")
	}
	dk := pbkdf2.Key([]byte(masterPassword), salt,
		masterKeyIterations, masterKeyLen, masterKeyHashFunc)
	return subtle.NewAESGCM(dk)
}
