package tinkreader

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"

	"github.com/gogo/protobuf/proto"
	"github.com/google/tink/go/subtle/aead"
	"github.com/google/tink/go/tink"
	"golang.org/x/crypto/pbkdf2"

	tinkpb "github.com/google/tink/proto/tink_go_proto"
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

// EncryptedKeysetReader reads encrypted keysets from disk.
// EncryptedKeysetReader implements tink.KeysetReader.
type EncryptedKeysetReader struct {
	File, Password string
}

// Read returns a (cleartext) Keyset object from the underlying source.
func (r *EncryptedKeysetReader) Read() (*tinkpb.Keyset, error) {
	encryptedKeyset, err := r.ReadEncrypted()
	if err != nil {
		return nil, err
	}
	masterKey, err := masterPBKDF(r.Password)
	if err != nil {
		return nil, err
	}
	return decryptKeyset(encryptedKeyset, masterKey)
}

// ReadEncrypted returns an EncryptedKeyset object from the underlying source.
func (r *EncryptedKeysetReader) ReadEncrypted() (*tinkpb.EncryptedKeyset, error) {
	data, err := ioutil.ReadFile(r.File)
	if err != nil {
		return nil, fmt.Errorf("reading keystore file %q failed: %v", r.File, err)
	}

	encryptedKeyset := new(tinkpb.EncryptedKeyset)
	if err := proto.Unmarshal(data, encryptedKeyset); err != nil {
		return nil, fmt.Errorf("could not parse encrypted keyset: %v", err)
	}
	return encryptedKeyset, nil
}

func decryptKeyset(encryptedKeyset *tinkpb.EncryptedKeyset, masterKey tink.AEAD) (*tinkpb.Keyset, error) {
	decrypted, err := masterKey.Decrypt(encryptedKeyset.EncryptedKeyset, []byte{})
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %s", err)
	}
	keyset := new(tinkpb.Keyset)
	if err := proto.Unmarshal(decrypted, keyset); err != nil {
		return nil, fmt.Errorf("invalid encrypted keyset")
	}
	return keyset, nil
}

// masterPBKDF converts the master password into the master key.
func masterPBKDF(masterPassword string) (tink.AEAD, error) {
	if masterPassword == "" {
		return nil, fmt.Errorf("please provide a master password")
	}
	dk := pbkdf2.Key([]byte(masterPassword), salt,
		masterKeyIterations, masterKeyLen, masterKeyHashFunc)
	return aead.NewAESGCM(dk)
}
