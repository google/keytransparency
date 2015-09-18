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

// This package contains common type definitions and functions used by other
// packages. Types that can cause circular import should be added here.
package common

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	proto "github.com/golang/protobuf/proto"
	v2pb "github.com/google/e2e-key-server/proto/v2"
)

const (
	commitmentKeyLen = 16
)

// Commitment returns the commitment key and the profile commitment
func Commitment(userID string, profile []byte) ([]byte, []byte, error) {
	// Generate commitment key.
	key := make([]byte, commitmentKeyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, nil, grpc.Errorf(codes.Internal, "Error generating key: %v", err)
	}

	mac := hmac.New(sha512.New, key)
	mac.Write([]byte(userID))
	mac.Write(profile)
	return key, mac.Sum(nil), nil
}

// VerifyCommitment returns nil if the profile commitment using the
// key matches the provided commitment, and error otherwise.
func VerifyCommitment(userID string, key, profile, commitment []byte) error {
	mac := hmac.New(sha512.New, key)
	mac.Write([]byte(userID))
	mac.Write(profile)
	if !hmac.Equal(mac.Sum(nil), commitment) {
		return grpc.Errorf(codes.InvalidArgument, "Invalid profile commitment")
	}
	return nil
}

// Hash calculates the hash of the given data.
func Hash(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}

// EpochHead unmarshal and returns SignedEpochHead.EpochHead.
func EpochHead(signedHead *v2pb.SignedEpochHead) (*v2pb.EpochHead, error) {
	epochHead := new(v2pb.EpochHead)
	if err := proto.Unmarshal(signedHead.EpochHead, epochHead); err != nil {
		return nil, grpc.Errorf(codes.InvalidArgument, "Cannot unmarshal epoch head")
	}
	return epochHead, nil
}
