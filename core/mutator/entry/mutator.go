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
	"errors"
	"sort"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/signature"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/google/keytransparency/core/mutator"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
)

// MapLogItemFn maps elements from *mutator.LogMessage to KV<index, *pb.EntryUpdate>.
func MapLogItemFn(m *mutator.LogMessage,
	emit func(index []byte, mutation *pb.EntryUpdate), emitErr func(error)) {
	var entry pb.Entry
	if err := proto.Unmarshal(m.Mutation.Entry, &entry); err != nil {
		emitErr(err)
		return
	}
	emit(entry.Index, &pb.EntryUpdate{
		Mutation:  m.Mutation,
		Committed: m.ExtraData,
	})
}

// IsValidEntry checks the internal consistency and correctness of a mutation.
func IsValidEntry(signedEntry *pb.SignedEntry) error {
	// Ensure that the mutation size is within bounds.
	if got, want := proto.Size(signedEntry), mutator.MaxMutationSize; got > want {
		glog.Warningf("mutation is %v bytes, want <= %v", got, want)
		return mutator.ErrSize
	}

	newEntry := pb.Entry{}
	if err := proto.Unmarshal(signedEntry.GetEntry(), &newEntry); err != nil {
		return status.Errorf(codes.InvalidArgument, "proto.Unmarshal(): %v", err)
	}

	ks, err := keyset.ReadWithNoSecrets(keyset.NewBinaryReader(
		bytes.NewBuffer(newEntry.GetAuthorizedKeyset())))
	if err != nil {
		return err
	}
	return verifyKeys(ks, signedEntry.GetEntry(), signedEntry.GetSignatures())
}

// ReduceFn decides which of multiple updates can be applied in this revision.
func ReduceFn(leaves []*pb.EntryUpdate, msgs []*pb.EntryUpdate,
	emit func(*pb.EntryUpdate), emitErr func(error)) {
	if got := len(leaves); got > 1 {
		emitErr(status.Errorf(codes.Internal, "got %v map leaves, want 0 or 1", got))
		return // A bad index should not cause the whole batch to fail.
	}
	var oldValue *pb.SignedEntry // If no map leaf was found, oldValue will be nil.
	if len(leaves) > 0 {
		oldValue = leaves[0].GetMutation()
	}

	if len(msgs) == 0 {
		emitErr(errors.New("no msgs"))
		return // A bad index should not cause the whole batch to fail.
	}

	// Filter for mutations that are valid.
	newEntries := make([]*pb.EntryUpdate, 0, len(msgs))
	for i, msg := range msgs {
		newValue, err := MutateFn(oldValue, msg.GetMutation())
		if err != nil {
			s := status.Convert(err)
			emitErr(status.Errorf(s.Code(), "entry: ReduceFn(msg %d/%d): %v", i+1, len(msgs), s.Message()))
			continue
		}
		newEntries = append(newEntries, &pb.EntryUpdate{
			Mutation:  newValue,
			Committed: msg.GetCommitted(),
		})
	}
	if len(newEntries) == 0 {
		return // No valid mutations for one index should not cause the whole batch to fail.
	}
	// Choose the mutation deterministically, regardless of the messages order.
	sort.Slice(newEntries, func(i, j int) bool {
		iHash := sha256.Sum256(newEntries[i].GetMutation().GetEntry())
		jHash := sha256.Sum256(newEntries[j].GetMutation().GetEntry())
		return bytes.Compare(iHash[:], jHash[:]) < 0
	})
	emit(newEntries[0])
}

// MutateFn verifies that newSignedEntry is a valid mutation for oldSignedEntry and returns the
// application of newSignedEntry to oldSignedEntry.
func MutateFn(oldSignedEntry, newSignedEntry *pb.SignedEntry) (*pb.SignedEntry, error) {
	if err := IsValidEntry(newSignedEntry); err != nil {
		return nil, err
	}

	newEntry := pb.Entry{}
	if err := proto.Unmarshal(newSignedEntry.GetEntry(), &newEntry); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "proto.Unmarshal(): %v", err)
	}
	oldEntry := pb.Entry{}
	// oldSignedEntry may be nil, resulting an empty oldEntry struct.
	if err := proto.Unmarshal(oldSignedEntry.GetEntry(), &oldEntry); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "proto.Unmarshal(): %v", err)
	}

	// Check if this mutation is a replay.
	if bytes.Equal(oldSignedEntry.GetEntry(), newSignedEntry.Entry) {
		glog.Warningf("mutation is a replay of an old one")
		return nil, mutator.ErrReplay
	}

	// Verify check-set semantics if Previous has been explicitly set.
	if want := newEntry.GetPrevious(); want != nil {
		prevEntryHash := sha256.Sum256(oldSignedEntry.GetEntry())
		if got := prevEntryHash[:]; !bytes.Equal(got, want) {
			glog.Warningf("previous entry hash: %x, want %x", got, want)
			return nil, mutator.ErrPreviousHash
		}
	}

	if oldSignedEntry == nil {
		// Skip verificaion checks if there is no previous oldSignedEntry.
		return newSignedEntry, nil
	}

	handle, err := keyset.ReadWithNoSecrets(keyset.NewBinaryReader(
		bytes.NewBuffer(oldEntry.GetAuthorizedKeyset())))
	if err != nil {
		return nil, err
	}
	if err := verifyKeys(handle, newSignedEntry.Entry, newSignedEntry.GetSignatures()); err != nil {
		return nil, err
	}

	return newSignedEntry, nil
}

// verifyKeys verifies both old and new authorized keys based on the following
// criteria:
//   1. At least one signature with a key in the entry should exist.
//   2. Signatures with no matching keys are simply ignored.
func verifyKeys(handle *keyset.Handle, data []byte, sigs [][]byte) error {
	if handle == nil {
		return errors.New("entry: nil keyset")
	}
	verifier, err := signature.NewVerifier(handle)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "signature.NewVerifier(%v): %v", handle, err)
	}

	for _, sig := range sigs {
		if err := verifier.Verify(sig, data); err == nil {
			return nil
		}
	}
	return mutator.ErrUnauthorized
}
