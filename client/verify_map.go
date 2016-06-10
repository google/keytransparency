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

package client

import (
	"crypto/hmac"
	"log"
	"time"

	"github.com/google/e2e-key-server/tree"
	"github.com/google/e2e-key-server/tree/sparse/memtree"

	"github.com/golang/protobuf/proto"

	ctmap "github.com/google/e2e-key-server/proto/security_ctmap"
	ts "github.com/google/e2e-key-server/proto/security_protobuf"
)

const (
	maxEpochDelay   = 60 * time.Minute
	verificationKey = "" // TODO: Fill with the map's signing key.
)

var (
	initialSEH = &ctmap.EpochHead{
		Epoch: 0,
		Root:  []byte(""), // TODO: Fill with inital SEH.
		IssueTime: &ts.Timestamp{
			Seconds: 0,
		},
	}
)

type MapClient struct {
	epochHead *ctmap.EpochHead
	factory   tree.SparseFactory
}

// TODO: Allow a MapClient to be loaded from disk with a trusted SEH.

func NewMapClient() *MapClient {
	return &MapClient{
		factory:   memtree.NewFactory(),
		epochHead: initialSEH,
	}
}

func (mc *MapClient) TrustedEpoch() int64 {
	return mc.epochHead.Epoch
}

func (mc *MapClient) AdvanceSEH(sehResp *ctmap.GetSTHResponse, proof *ctmap.GetConsistencyProofResponse) bool {
	// Verify that the SEH is signed by a trusted party.
	// TODO: Is there a signature from the correct domain?
	// TODO: Is there a signature from 1 or more trusted monitors?

	// TODO: Verify that seh is an append-only update from mc.epochHead
	// TODO: Verify against monitors

	if sehResp != nil {
		epochHead := new(ctmap.EpochHead)
		if err := proto.Unmarshal(sehResp.Sth.EpochHead, epochHead); err != nil {
			log.Printf("Error unmarshaling EpochHead: %v", err)
			return false
		}
		mc.epochHead = epochHead
	}
	return true
}

// VerifyLeafProof returns true if the neighbor hashes and entry chain up to the expectedRoot.
func (mc *MapClient) VerifyLeafProof(index []byte, leafproof *ctmap.GetLeafResponse) bool {
	// TODO: replace with static merkle tree
	m := mc.factory.FromNeighbors(leafproof.Neighbors, index, leafproof.LeafData)
	calculatedRoot, _ := m.ReadRoot(nil)
	return hmac.Equal(mc.epochHead.Root, calculatedRoot)
}
