// Copyright 2015 Google Inc. All Rights Reserved.
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

// package replace implements a simple replacement stragey as a mapper
package entry

import (
	"bytes"

	"github.com/golang/protobuf/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	ctmap "github.com/google/e2e-key-server/proto/security_ctmap"
)

// Replace defines mutations to simply replace the current map value with the
// contents of the mutation.
type Entry struct{}

func New() *Entry {
	return &Entry{}
}

// CheckMutation verifies that this is a valid mutation for this item.
func (e *Entry) CheckMutation(value, mutation []byte) error {
	signedEntryUpdate := &ctmap.SignedEntryUpdate{}
	if err := proto.Unmarshal(mutation, signedEntryUpdate); err != nil {
		return grpc.Errorf(codes.Internal, "Cannot unmarshal signedEntryUpdate")
	}
	newEntry := &ctmap.Entry{}
	if err := proto.Unmarshal(signedEntryUpdate.NewEntry, newEntry); err != nil {
		return grpc.Errorf(codes.Internal, "Cannot unmarshal signedEntryUpdate.Entry")
	}
	if value != nil {
		oldEntry := &ctmap.Entry{}
		if err := proto.Unmarshal(value, oldEntry); err != nil {
			return grpc.Errorf(codes.Internal, "Cannot unmarshal Entry")
		}
		if !bytes.Equal(oldEntry.Index, newEntry.Index) {
			return grpc.Errorf(codes.Internal, "New index=%v, want %v", newEntry.Index, oldEntry.Index)
		}
		// TODO: Verify signatures in mutation with the keys in value.
	}
	return nil
}

// Mutate applies mutation to value
func (e *Entry) Mutate(value, mutation []byte) ([]byte, error) {
	signedEntryUpdate := &ctmap.SignedEntryUpdate{}
	if err := proto.Unmarshal(mutation, signedEntryUpdate); err != nil {
		return nil, grpc.Errorf(codes.Internal, "Cannot unmarshal signedEntryUpdate")
	}

	return signedEntryUpdate.NewEntry, nil
}
