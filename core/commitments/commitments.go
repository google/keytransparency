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

	"golang.org/x/net/context"

	pb "github.com/google/key-transparency/proto/keytransparency_v1"
)

const (
	// commitmentKeyLen should be robust against the birthday attack.
	// One commitment is given for each leaf node throughout time.
	commitmentKeyLen = 16 // 128 bits of security, supports 2^64 nodes.
)

var (
	hashAlgo = sha512.New512_256
	// ErrInvalidCommitment occurs when the commitment doesn't match the profile.
	ErrInvalidCommitment = errors.New("invalid commitment")
)

// Committer saves cryptographic commitments.
type Committer interface {
	// Write saves a cryptographic commitment and associated data.
	Write(ctx context.Context, commitment []byte, committed *pb.Committed) error
	// Read looks up a cryptograpic commitment and returns associated data.
	Read(ctx context.Context, commitment []byte) (*pb.Committed, error)
}

// Commit makes a cryptographic commitment under a specific userID to data.
func Commit(userID string, data []byte) ([]byte, *pb.Committed, error) {
	// Generate commitment key.
	key := make([]byte, commitmentKeyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, nil, err
	}

	mac := hmac.New(hashAlgo, key)
	mac.Write([]byte(userID))
	mac.Write([]byte{0}) // Separate userID from data.
	mac.Write(data)
	return mac.Sum(nil), &pb.Committed{Key: key, Data: data}, nil
}

// Verify customizes a commitment with a userID.
func Verify(userID string, commitment []byte, committed *pb.Committed) error {
	mac := hmac.New(hashAlgo, committed.Key)
	mac.Write([]byte(userID))
	mac.Write([]byte{0})
	mac.Write(committed.Data)
	if !hmac.Equal(mac.Sum(nil), commitment) {
		return ErrInvalidCommitment
	}
	return nil
}
