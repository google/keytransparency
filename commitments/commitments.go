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
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"errors"

	"golang.org/x/net/context"

	pb "github.com/google/key-transparency/proto/security_e2ekeys_v1"
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

// Commit returns the commitment key and the commitment
func Commit(data []byte) ([]byte, *pb.Committed, error) {
	// Generate commitment key.
	key := make([]byte, commitmentKeyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, nil, err
	}

	mac := hmac.New(hashAlgo, key)
	mac.Write(data)
	return mac.Sum(nil), &pb.Committed{key, data}, nil
}

// CommitName makes a cryptographic commitment under a specific userID to data.
func CommitName(userID string, data []byte) ([]byte, *pb.Committed, error) {
	d := bytes.NewBufferString(userID)
	d.Write(data)
	commitment, committed, err := Commit(d.Bytes())
	return commitment, &pb.Committed{committed.Key, data}, err
}

// Verify returns nil if the commitment is valid.
func Verify(commitment []byte, committed *pb.Committed) error {
	mac := hmac.New(hashAlgo, committed.Key)
	mac.Write(committed.Data)
	if !hmac.Equal(mac.Sum(nil), commitment) {
		return ErrInvalidCommitment
	}
	return nil
}

// VerifyName customizes a commitment with a userID.
func VerifyName(userID string, commitment []byte, committed *pb.Committed) error {
	d := bytes.NewBufferString(userID)
	d.Write(committed.Data)
	return Verify(commitment, &pb.Committed{committed.Key, d.Bytes()})
}
