package tinkreader

import (
	"fmt"
	"io/ioutil"

	"github.com/gogo/protobuf/proto"
	"github.com/google/tink/go/tink"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

// KeysetWriter knows how to write a Keyset or an EncryptedKeyset to some source.
type KeysetWriter interface {
	// Write keyset to some storage system.
	Write(Keyset *tinkpb.Keyset) error

	// Write EncryptedKeyset to some storage system.
	WriteEncrypted(keyset *tinkpb.EncryptedKeyset) error
}

// EncryptedKeysetWriter writes encrypted keysets to disk.
type EncryptedKeysetWriter struct {
	File, Password string
}

// Write encrypts and writes the keyset to disk.
func (w *EncryptedKeysetWriter) Write(keyset *tinkpb.Keyset) error {
	masterKey, err := masterPBKDF(w.Password)
	if err != nil {
		return err
	}
	encryptedKeyset, err := encryptKeyset(keyset, masterKey)
	if err != nil {
		return err
	}
	return w.WriteEncrypted(encryptedKeyset)
}

// WriteEncrypted writes the keyset to disk.
func (w *EncryptedKeysetWriter) WriteEncrypted(keyset *tinkpb.EncryptedKeyset) error {
	serialized, err := proto.Marshal(keyset)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(w.File, serialized, 0600)
}

func encryptKeyset(keyset *tinkpb.Keyset, masterKey tink.AEAD) (*tinkpb.EncryptedKeyset, error) {
	serializedKeyset, err := proto.Marshal(keyset)
	if err != nil {
		return nil, fmt.Errorf("invalid keyset")
	}
	encrypted, err := masterKey.Encrypt(serializedKeyset, []byte{})
	if err != nil {
		return nil, fmt.Errorf("encrypted failed: %s", err)
	}
	// get keyset info
	info, err := tink.GetKeysetInfo(keyset)
	if err != nil {
		return nil, fmt.Errorf("cannot get keyset info: %s", err)
	}
	encryptedKeyset := &tinkpb.EncryptedKeyset{
		EncryptedKeyset: encrypted,
		KeysetInfo:      info,
	}
	return encryptedKeyset, nil
}
