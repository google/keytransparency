// Copyright 2016 Google Inc. All Rights Reserved.
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

// Package commitments contains common type definitions and functions used by other
// packages. Types that can cause circular import should be added here.
package commitments

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"errors"

	"github.com/benlaurie/objecthash/go/objecthash"
	"github.com/golang/protobuf/ptypes/any"
	"golang.org/x/net/context"

	tpb "github.com/google/key-transparency/core/proto/kt_types_v1"
)

const (
	// commitmentKeyLen should be robust against the birthday attack.
	// One commitment is given for each leaf node throughout time.
	commitmentKeyLen = 16 // 128 bits of security, supports 2⁶⁴ nodes.
)

var (
	hashAlgo = sha512.New512_256
	// ErrInvalidCommitment occurs when the commitment doesn't match the profile.
	ErrInvalidCommitment = errors.New("invalid commitment")
	// randReader supports testing with static keys
	randReader = rand.Read
)

// Committer saves cryptographic commitments.
type Committer interface {
	// Write saves a cryptographic commitment and associated data.
	Write(ctx context.Context, commitment []byte, committed *tpb.Committed) error
	// Read looks up a cryptograpic commitment and returns associated data.
	Read(ctx context.Context, commitment []byte) (*tpb.Committed, error)
}

// Commit creates a cryptographic commitment to a protobuf message and a userID.
func Commit(userID string, a *any.Any) ([]byte, *tpb.Committed, error) {
	// Generate commitment key.
	key := make([]byte, commitmentKeyLen)
	if _, err := randReader(key); err != nil {
		return nil, nil, err
	}

	mac := hmac.New(hashAlgo, key)
	mac.Write([]byte(userID))
	mac.Write([]byte{0}) // Separate userID from data.
	h := objecthash.ObjectHash(a)
	mac.Write(h[:])
	return mac.Sum(nil), &tpb.Committed{Key: key, Data: a}, nil
}

// Verify verifies that the cryptographic commitment to the message and userID is correct.
func Verify(userID string, commitment []byte, committed *tpb.Committed) error {
	mac := hmac.New(hashAlgo, committed.Key)
	mac.Write([]byte(userID))
	mac.Write([]byte{0}) // Separate userID from data.
	h := objecthash.ObjectHash(committed.Data)
	mac.Write(h[:])

	if !hmac.Equal(mac.Sum(nil), commitment) {
		return ErrInvalidCommitment
	}
	return nil
}
