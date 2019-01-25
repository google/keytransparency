package tinkreader

import (
	"fmt"
	"io/ioutil"

	"github.com/gogo/protobuf/proto"

	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

// ProtoKeysetFile reads and writes keysets from disk.
type ProtoKeysetFile struct {
	File string
}

// Read returns a (cleartext) Keyset object from disk.
func (p *ProtoKeysetFile) Read() (*tinkpb.Keyset, error) {
	data, err := ioutil.ReadFile(p.File)
	if err != nil {
		return nil, fmt.Errorf("reading file %q failed: %v", p.File, err)
	}

	keyset := new(tinkpb.Keyset)
	if err := proto.Unmarshal(data, keyset); err != nil {
		return nil, fmt.Errorf("could not parse keyset: %v", err)
	}
	return keyset, nil
}

// Write the keyset to disk.
func (p *ProtoKeysetFile) Write(keyset *tinkpb.Keyset) error {
	serialized, err := proto.Marshal(keyset)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(p.File, serialized, 0600)
}

// ReadEncrypted returns an EncryptedKeyset object from disk.
func (p *ProtoKeysetFile) ReadEncrypted() (*tinkpb.EncryptedKeyset, error) {
	data, err := ioutil.ReadFile(p.File)
	if err != nil {
		return nil, fmt.Errorf("reading file %q failed: %v", p.File, err)
	}

	encryptedKeyset := new(tinkpb.EncryptedKeyset)
	if err := proto.Unmarshal(data, encryptedKeyset); err != nil {
		return nil, fmt.Errorf("could not parse encrypted keyset: %v", err)
	}
	return encryptedKeyset, nil
}

// WriteEncrypted the encrypted keyset to disk.
func (p *ProtoKeysetFile) WriteEncrypted(keyset *tinkpb.EncryptedKeyset) error {
	serialized, err := proto.Marshal(keyset)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(p.File, serialized, 0600)
}
