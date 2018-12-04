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
	"crypto/sha256"
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/tink"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/google/keytransparency/core/crypto/commitments"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

var nilHash = sha256.Sum256(nil)

// Mutation provides APIs for manipulating entries.
type Mutation struct {
	UserID      string
	data, nonce []byte

	prevEntry       *pb.Entry
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
			Index:    index,
			Previous: nilHash[:],
		},
	}
}

// SetPrevious sets the previous hash.
// If copyPrevious is true, AuthorizedKeys and Commitment are also copied.
func (m *Mutation) SetPrevious(oldValue []byte, copyPrevious bool) error {
	prevSignedEntry, err := FromLeafValue(oldValue)
	if err != nil {
		return err
	}
	m.prevSignedEntry = prevSignedEntry

	hash := sha256.Sum256(prevSignedEntry.GetEntry())
	m.entry.Previous = hash[:]

	var prevEntry pb.Entry
	if err := proto.Unmarshal(prevSignedEntry.GetEntry(), &prevEntry); err != nil {
		return err
	}
	if copyPrevious {
		m.entry.AuthorizedKeys = prevEntry.GetAuthorizedKeys()
		m.entry.Commitment = prevEntry.GetCommitment()
	}
	return nil
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
func (m *Mutation) ReplaceAuthorizedKeys(pubkeys *tinkpb.Keyset) error {
	// Make sure that pubkeys is a valid keyset.
	if _, err := tink.KeysetHandleWithNoSecret(pubkeys); err != nil {
		return err
	}

	m.entry.AuthorizedKeys = pubkeys
	return nil
}

// SerializeAndSign produces the mutation.
func (m *Mutation) SerializeAndSign(signers []*tink.KeysetHandle) (*pb.EntryUpdate, error) {
	mutation, err := m.sign(signers)
	if err != nil {
		return nil, err
	}

	// Check authorization.
	if err := verifyKeys(m.prevEntry.GetAuthorizedKeys(), m.entry.GetAuthorizedKeys(),
		mutation.Entry, mutation.Signatures); err != nil {
		return nil, status.Errorf(codes.PermissionDenied,
			"verifyKeys(oldKeys: %v, newKeys: %v, sigs: %v): %v",
			len(m.prevEntry.GetAuthorizedKeys().GetKey()),
			len(m.entry.GetAuthorizedKeys().GetKey()),
			len(mutation.GetSignatures()), err)
	}

	// Sanity check the mutation's correctness.
	if _, err := MutateFn(m.prevSignedEntry, mutation); err != nil {
		return nil, fmt.Errorf("presign mutation check: %v", err)
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
func (m *Mutation) sign(signers []*tink.KeysetHandle) (*pb.SignedEntry, error) {
	entryData, err := proto.Marshal(m.entry)
	if err != nil {
		return nil, fmt.Errorf("proto.Marshal(): %v", err)
	}

	sigs := make([][]byte, 0, len(signers))
	for _, handle := range signers {
		signer, err := signature.NewSigner(handle)
		if err != nil {
			return nil, err
		}
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
