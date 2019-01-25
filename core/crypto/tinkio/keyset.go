package tinkio

import (
	"fmt"

	"github.com/gogo/protobuf/proto"
	"github.com/google/tink/go/insecure"
	"github.com/google/tink/go/tink"

	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

//
// This file should be moved into the tink package.
//

// KeysetWriter knows how to write a Keyset or an EncryptedKeyset to some source.
type KeysetWriter interface {
	// Write keyset to some storage system.
	Write(Keyset *tinkpb.Keyset) error

	// Write EncryptedKeyset to some storage system.
	WriteEncrypted(keyset *tinkpb.EncryptedKeyset) error
}

// KeysetHandleFromEncryptedReader reads and decrypts an encrypted keyset.
func KeysetHandleFromEncryptedReader(reader tink.KeysetReader, masterKey tink.AEAD) (*tink.KeysetHandle, error) {
	encryptedKeyset, err := reader.ReadEncrypted()
	if err != nil {
		return nil, err
	}
	return decrypt(encryptedKeyset, masterKey)
}

// WriteKeyset encrypts and writes an encrypted keyset.
func WriteKeyset(keyset *tink.KeysetHandle, writer KeysetWriter, masterKey tink.AEAD) error {
	encrypted, err := encrypt(keyset, masterKey)
	if err != nil {
		return err
	}
	return writer.WriteEncrypted(encrypted)
}

func decrypt(encryptedKeyset *tinkpb.EncryptedKeyset, masterKey tink.AEAD) (*tink.KeysetHandle, error) {
	decrypted, err := masterKey.Decrypt(encryptedKeyset.EncryptedKeyset, []byte{})
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %s", err)
	}
	return insecure.KeysetHandleFromSerializedProto(decrypted)
}

func encrypt(keyset *tink.KeysetHandle, masterKey tink.AEAD) (*tinkpb.EncryptedKeyset, error) {
	serializedKeyset, err := proto.Marshal(keyset.Keyset())
	if err != nil {
		return nil, fmt.Errorf("invalid keyset")
	}
	encrypted, err := masterKey.Encrypt(serializedKeyset, []byte{})
	if err != nil {
		return nil, fmt.Errorf("encrypted failed: %s", err)
	}
	// get keyset info
	info, err := tink.GetKeysetInfo(keyset.Keyset())
	if err != nil {
		return nil, fmt.Errorf("cannot get keyset info: %s", err)
	}
	encryptedKeyset := &tinkpb.EncryptedKeyset{
		EncryptedKeyset: encrypted,
		KeysetInfo:      info,
	}
	return encryptedKeyset, nil
}
