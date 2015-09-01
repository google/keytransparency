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
	"math/big"
	"fmt"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"reflect"
	"encoding/binary"
	"encoding/hex"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	proto "github.com/golang/protobuf/proto"
	v2pb "github.com/google/e2e-key-server/proto/v2"
)

const (
	// HashSize contains the blocksize of the used hash function in bytes.
	HashSize = sha256.Size
	// IndexLen is the maximum number of levels in this Merkle Tree.
	IndexLen = HashSize * 8
	// commitmentKeyLen is the number of bytes required to be in the
	// profile commitment.
	commitmentKeyLen = 16
)

var (
	// TreeNonce is a constant value used as a salt in all leaf node calculations.
	// The TreeNonce prevents different realms from producing collisions.
	TreeNonce = []byte{241, 71, 100, 55, 62, 119, 69, 16, 150, 179, 228, 81, 34, 200, 144, 6}
	// LeafIdentifier is the data used to indicate a leaf node.
	LeafIdentifier = []byte("L")
	// EmptyIdentifier is used while calculating the data of nil sub branches.
	EmptyIdentifier = []byte("E")
)

// Commitment returns the commitment key and the profile commitment
func Commitment(profile []byte) ([]byte, []byte, error) {
	// Generate commitment key.
	key := make([]byte, commitmentKeyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, nil, grpc.Errorf(codes.Internal, "Error generating key: %v", err)
	}

	mac := hmac.New(sha512.New, key)
	mac.Write(profile)
	return key, mac.Sum(nil), nil
}

// VerifyCommitment returns nil if the profile commitment using the
// key matches the provided commitment, and error otherwise.
func VerifyCommitment(key []byte, profile []byte, commitment []byte) error {
	mac := hmac.New(sha512.New, key)
	mac.Write(profile)
	if !hmac.Equal(mac.Sum(nil), commitment) {
		return grpc.Errorf(codes.InvalidArgument, "Invalid profile commitment")
	}
	return nil
}

// HashLeaf calculate the merkle tree leaf node value. This is computed as
// H(TreeNonce || Identifier || depth || index || dataHash), where TreeNonce,
// Identifier, depth, and index are fixed-length.
func HashLeaf(identifier []byte, depth int, index []byte, dataHash []byte) []byte {
	bdepth := make([]byte, 4)
	binary.BigEndian.PutUint32(bdepth, uint32(depth))

	h := sha256.New()
	h.Write(TreeNonce)
	h.Write(identifier)
	h.Write(bdepth)
	h.Write(index)
	h.Write(dataHash)
	return h.Sum(nil)
}

// HashIntermediateNode calculates an interior node's value by H(left || right)
func HashIntermediateNode(left []byte, right []byte) []byte {
	h := sha256.New()
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// EmptyLeafValue computes the value of an empty leaf as
// H(TreeNonce || EmptyIdentifier || depth || index), where TreeNonce,
// EmptyIdentifier, depth, and index are fixed-length.
func EmptyLeafValue(prefix string) []byte {
	return HashLeaf(EmptyIdentifier, len(prefix), []byte(prefix), nil)
}

// Hash calculates the hash of the given data.
func Hash(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}

// InspectHead ensures that the given expected and calculated head values
// matches and returns an error otherwise.
func InspectHead(expectedHeadValue []byte, calculatedHeadValue []byte) error {
	// Ensure that the head expected value is equal to the computed one.
	if !reflect.DeepEqual(expectedHeadValue, calculatedHeadValue) {
		return grpc.Errorf(codes.InvalidArgument, "Invalid merkle tree neighbors list")
	}
	return nil
}

// GetHeadValue returns the head value from signedHead.Head.Head.
func GetHeadValue(signedHead *v2pb.SignedEpochHead) ([]byte, error) {
	timestampedHead := new(v2pb.TimestampedEpochHead)
	if err := proto.Unmarshal(signedHead.Head, timestampedHead); err != nil {
		return nil, grpc.Errorf(codes.InvalidArgument, "Cannot unmarshal timestamped epoch head")
	}
	return timestampedHead.Head.Head, nil
}

// BitString converts a byte slice index into a string of Depth '0' or '1'
// characters.
func BitString(index []byte) string {
	i := new(big.Int)
	i.SetString(hex.EncodeToString(index), 16)
	// A 256 character string of bits with leading zeros.
	return fmt.Sprintf("%0256b", i)
}
