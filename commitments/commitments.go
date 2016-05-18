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

// This package contains common type definitions and functions used by other
// packages. Types that can cause circular import should be added here.
package commitments

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"errors"

	"golang.org/x/net/context"
)

const (
	// commitmentKeyLen should be robust against the birthday attack. One
	// commitment is given for each leaf node throughout time.
	commitmentKeyLen = 16 //128 bits of security, supports 2^64 nodes
	Size             = sha512.Size256
)

var (
	hashAlgo             = sha512.New512_256
	errInvalidCommitment = errors.New("Invalid commitment")
)

type Commitment struct {
	// Commitment key
	Key []byte
	// Commitment value
	Data []byte
}

type Committer interface {
	// TODO: remove ctx
	// TODO: rename WriteCommitment to Commit
	WriteCommitment(ctx context.Context, commitment, key, value []byte) error
	ReadCommitment(ctx context.Context, commitment []byte) (*Commitment, error)
}

// Commit returns the commitment key and the commitment
func Commit(data []byte) ([]byte, []byte, error) {
	// Generate commitment key.
	key := make([]byte, commitmentKeyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, nil, err
	}

	mac := hmac.New(hashAlgo, key)
	mac.Write(data)
	return key, mac.Sum(nil), nil
}

func CommitName(userID string, data []byte) ([]byte, []byte, error) {
	d := bytes.NewBufferString(userID)
	d.Write(data)
	return Commit(d.Bytes())
}

// Verify returns nil if the commitment is valid.
func Verify(key, data, commitment []byte) error {
	mac := hmac.New(hashAlgo, key)
	mac.Write(data)
	if !hmac.Equal(mac.Sum(nil), commitment) {
		return errInvalidCommitment
	}
	return nil
}

// VerifyName customizes a commitment with a userID.
func VerifyName(userID string, key, data, commitment []byte) error {
	d := bytes.NewBufferString(userID)
	d.Write(data)
	return Verify(key, d.Bytes(), commitment)
}
