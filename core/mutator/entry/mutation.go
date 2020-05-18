// Copyright 2017 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package entry

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/google/keytransparency/core/crypto/commitments"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/tink"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
)

// Mutation provides APIs for manipulating entries.
type Mutation struct {
	UserID      string
	data, nonce []byte

	prevRev         uint64
	prevSignedEntry *pb.SignedEntry
	entry           *pb.Entry
	signedEntry     *pb.SignedEntry
}

// NewMutation creates a mutation object from a previous value which can be modified.
// To create a new value:
// - Create a new mutation for a user starting with the previous value with NewMutation.
// - Change the value with SetCommitment and ReplaceAuthorizedKeys.
// - Finalize the changes and create the mutation with SerializeAndSign.
func NewMutation(index []byte, directoryID, userID string) *Mutation {
	return &Mutation{
		UserID: userID,
		entry: &pb.Entry{
			Index: index,
		},
	}
}

// SetPrevious adds a check-set constraint on the mutation which is useful when performing a get-modify-set operation.
//
// If Previous is set, the server will verify that the *current* value matches the Previous hash in this mutation.
// If the hash is missmatched, the server will not apply the mutation.
// If Previous is unset, the server will not perform this check.
//
// If copyPrevious is true, AuthorizedKeys and Commitment are also copied.
// oldValueRevision is the map revision that oldValue was fetched at.
func (m *Mutation) SetPrevious(oldValueRevision uint64, oldValue []byte, copyPrevious bool) error {
	prevSignedEntry, err := FromLeafValue(oldValue)
	if err != nil {
		return err
	}
	m.prevRev = oldValueRevision
	m.prevSignedEntry = prevSignedEntry

	hash := sha256.Sum256(prevSignedEntry.GetEntry())
	m.entry.Previous = hash[:]

	var prevEntry pb.Entry
	if err := proto.Unmarshal(prevSignedEntry.GetEntry(), &prevEntry); err != nil {
		return err
	}
	if copyPrevious {
		m.entry.AuthorizedKeyset = prevEntry.GetAuthorizedKeyset()
		m.entry.Commitment = prevEntry.GetCommitment()
	}
	return nil
}

// MinApplyRevision returns the minimum revision that a client can reasonably
// expect this mutation to be applied in.  Clients should wait until a current
// map revision > MinApplyRevision before attempting to verify that a mutation
// has succeeded.
func (m *Mutation) MinApplyRevision() int64 {
	return int64(m.prevRev) + 1
}

// SetCommitment updates entry to be a commitment to data.
func (m *Mutation) SetCommitment(data []byte) error {
	// Commit to profile.
	commitmentNonce, err := commitments.GenCommitmentKey()
	if err != nil {
		return err
	}
	m.data = data
	m.nonce = commitmentNonce
	m.entry.Commitment = commitments.Commit(m.UserID, data, commitmentNonce)
	return nil
}

// ReplaceAuthorizedKeys sets authorized keys to pubkeys.
// pubkeys must contain at least one key.
func (m *Mutation) ReplaceAuthorizedKeys(handle *keyset.Handle) error {
	var b bytes.Buffer
	if err := handle.WriteWithNoSecrets(keyset.NewBinaryWriter(&b)); err != nil {
		return nil
	}
	m.entry.AuthorizedKeyset = b.Bytes()
	return nil
}

// SerializeAndSign produces the mutation.
func (m *Mutation) SerializeAndSign(signers []tink.Signer) (*pb.EntryUpdate, error) {
	mutation, err := m.sign(signers)
	if err != nil {
		return nil, err
	}

	// Sanity check the mutation's correctness.
	if _, err := MutateFn(m.prevSignedEntry, mutation); err != nil {
		return nil, err
	}

	return &pb.EntryUpdate{
		UserId:   m.UserID,
		Mutation: mutation,
		Committed: &pb.Committed{
			Key:  m.nonce,
			Data: m.data,
		},
	}, nil
}

// Sign produces the mutation
func (m *Mutation) sign(signers []tink.Signer) (*pb.SignedEntry, error) {
	entryData, err := proto.Marshal(m.entry)
	if err != nil {
		return nil, fmt.Errorf("proto.Marshal(): %v", err)
	}

	sigs := make([][]byte, 0, len(signers))
	for _, signer := range signers {
		sig, err := signer.Sign(entryData)
		if err != nil {
			return nil, err
		}
		sigs = append(sigs, sig)
	}

	m.signedEntry = &pb.SignedEntry{
		Entry:      entryData,
		Signatures: sigs,
	}
	return m.signedEntry, nil
}

// EqualsRequested verifies that an update was successfully applied.
// Returns nil if newLeaf is equal to the entry in this mutation.
func (m *Mutation) EqualsRequested(leafValue *pb.SignedEntry) bool {
	return proto.Equal(leafValue, m.signedEntry)
}

// EqualsPrevious returns true if the leafValue is equal to
// the value of entry at the time this mutation was made.
func (m *Mutation) EqualsPrevious(leafValue *pb.SignedEntry) bool {
	return proto.Equal(leafValue, m.prevSignedEntry)
}
