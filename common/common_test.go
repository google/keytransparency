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

package common

import (
	"testing"
	"encoding/hex"
	"crypto/rand"
	"strings"

	"github.com/golang/protobuf/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	v2pb "github.com/google/e2e-key-server/proto/v2"
)

const (
	// indexLen is the length of index in bytes.
	indexLen = HashSize
)

var AllZeros = strings.Repeat("0", 256)

// Instance represent a testing instance.
type Instance struct {
	// index is the index of the leaf node.
	index []byte
	// value contains the value of the leaf node we're trying to verify its
	// neighbors.
	value []byte
	// neighbors contains the list of neighbors.
	neighbors [][]byte
	// head contains the value of the head.
	head []byte
}

func hexToBytes(s string) ([]byte, error) {
	result, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func NewInstance(t *testing.T, depth int) *Instance {
	// Generate random index.
	index := make([]byte, indexLen)
	if _, err := rand.Read(index); err != nil {
		t.Fatalf("Error generating index: %v", err)
	}

	// Generate random value.
	value := make([]byte, HashSize)
	if _, err := rand.Read(value); err != nil {
		t.Fatalf("Error generating value: %v", err)
	}

	// Generating neighbors.
	neighbors, err := generateNeighbors(depth)
	if err != nil {
		t.Fatalf("Error generating neighbors: %v", err)
	}

	// Calculate the head
	head, err := buildPartialMerkleTree(neighbors, BitString(index), value)
	if err != nil {
		t.Fatalf("Error calculating head: %v", err)
	}

	return &Instance{index, value, neighbors, head}
}

func generateNeighbors(depth int) ([][]byte, error) {
	neighbors := make([][]byte, depth)
	for i, _ := range(neighbors) {
		neighbors[i] = make([]byte, HashSize)
		if _, err := rand.Read(neighbors[i]); err != nil {
			return nil, err
		}
	}
	return neighbors, nil
}

func TestBitString(t *testing.T) {
	tests := []struct {
		input  string
		output string
	}{
		{"00", AllZeros},
	}

	for i, test := range tests {
		index, err := hexToBytes(test.input)
		if err != nil {
			t.Fatalf("Hex decoding of '%v' failed: %v", test.input, err)
		}
		if got, want := BitString(index), test.output; got != want {
			t.Errorf("Test[%v]: BitString(%v)=%v, want %v", i, test.input, got, want)
		}
	}
}


func TestVerifyTreeNeighbors(t *testing.T) {
	tests := []struct {
		depth int
	}{
		{0},
		{1},
		{10},
		{256},
	}

	for i, test := range tests {
		instance := NewInstance(t, test.depth)

		timestampedHead := &v2pb.TimestampedEpochHead{
			Head: &v2pb.EpochHead{
				Head: instance.head,
			},
		}
		timestampedHeadData, err := proto.Marshal(timestampedHead)
		if err != nil {
			t.Fatalf("Cammot marshal timestamped epoch head")
		}
		seh := &v2pb.SignedEpochHead{
			Head: timestampedHeadData,
		}

		// Get the head value.
		headValue, err := GetHeadValue(seh)
		if err != nil {
			t.Fatalf("Getting head value failed")
		}

		err = VerifyMerkleTreeNeighbors(instance.neighbors, headValue, instance.index, instance.value)

		if got, want := grpc.Code(err), codes.OK; got != want {
			t.Errorf("Test[%v]: VerifyMerkleTreeNeighbors(depth=%v)=%v, want %v", i, test.depth, got, want)
		}
	}
}
