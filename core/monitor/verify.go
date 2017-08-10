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

// Package monitor implements the monitor service. A monitor repeatedly polls a
// key-transparency server's Mutations API and signs Map Roots if it could
// reconstruct
// clients can query.
package monitor

import (
	"crypto"
	"errors"
	"fmt"

	"github.com/golang/glog"

	// "github.com/google/trillian"
	// "github.com/google/trillian/merkle"
	"github.com/google/keytransparency/core/mutator/entry"

	tcrypto "github.com/google/trillian/crypto"

	"bytes"
	ktpb "github.com/google/keytransparency/core/proto/keytransparency_v1_types"
	"github.com/google/trillian"
	"github.com/google/trillian/merkle"
	"github.com/google/trillian/merkle/coniks"
	"github.com/google/trillian/storage"
)

var (
	// ErrInvalidMutation occurs when verification failed because of an invalid
	// mutation.
	ErrInvalidMutation = errors.New("invalid mutation")
	// ErrNotMatchingRoot occurs when the reconstructed root differs from the one
	// we received from the server.
	ErrNotMatchingRoot = errors.New("recreated root does not match")
	// ErrInvalidMapSignature occurs when the signature on the observed map root
	// is invalid.
	ErrInvalidMapSignature = errors.New("invalid signature on map in GetMutationsResponse")
	// ErrInvalidLogSignature occurs when the signature on the observed map root
	// is invalid.
	ErrInvalidLogSignature = errors.New("invalid signature on log in GetMutationsResponse")
)

// verifyResponse verifies a response received by the GetMutations API.
// Additionally to the response it takes a complete list of mutations. The list
// of received mutations may differ from those included in the initial response
// because of the max. page size.
func VerifyResponse(logPubKey, mapPubKey crypto.PublicKey, resp *ktpb.GetMutationsResponse, allMuts []*ktpb.Mutation) error {
	// verify signature on map root:
	if err := tcrypto.VerifyObject(mapPubKey, resp.GetSmr(), resp.GetSmr().GetSignature()); err != nil {
		glog.Errorf("couldn't verify signature on map root: %v", err)
		return ErrInvalidMapSignature
	}

	// verify signature on log-root:
	hash := tcrypto.HashLogRoot(*resp.GetLogRoot())
	if err := tcrypto.Verify(logPubKey, hash, resp.GetLogRoot().GetSignature()); err != nil {
		return ErrInvalidLogSignature
	}
	//hasher, err := hashers.NewLogHasher(trillian.HashStrategy_OBJECT_RFC6962_SHA256)
	//if err != nil {
	//	return nil, fmt.Errorf("Failed retrieving LogHasher from registry: %v", err)
	//}
	// logVerifier := merkle.NewLogVerifier(hasher)
	// logVerifier.VerifyConsistencyProof()
	// logVerifier.VerifyInclusionProof()

	// mapID := resp.GetSmr().GetMapId()
	if err := verifyMutations(allMuts, resp.GetSmr().GetRootHash(), resp.GetSmr().GetMapId()); err != nil {
		return err
	}

	return errors.New("TODO: implement verification logic")
}

func verifyMutations(muts []*ktpb.Mutation, expectedRoot []byte, mapID int64) error {
	// TODO: export applyMutations in CreateEpoch / signer.go?
	//

	// verify the mutation’s validity against the previous leaf.
	//
	// entry.VerifyKeys()
	// or
	// entry.Mutate() // does all checks and returns the new leaf as well
	inclusionMap := make(map[[32]byte]*trillian.MapLeafInclusion)
	updatedLeafMap := make(map[[32]byte]*trillian.MapLeaf)
	mutator := entry.New()
	oldProofNodes := make(map[string]*storage.Node)
	hasher := coniks.Default

	for _, m := range muts {
		// verify that the provided leaf’s inclusion proof goes to epoch e-1:
		//
		//if err := merkle.VerifyMapInclusionProof(mapID, index,
		//	leafHash, rootHash, proof, hasher); err != nil {
		//	glog.Errorf("VerifyMapInclusionProof(%x): %v", index, err)
		//	return ErrInvalidMutation
		//}
		leafVal, err := entry.FromLeafValue(m.GetProof().GetLeaf().GetLeafValue())
		if err != nil {
			return ErrInvalidMutation
		}
		newLeaf, err := mutator.Mutate(leafVal, m.GetUpdate())
		if err != nil {
			// TODO(ismail): do not return; collect other errors if any
			return ErrInvalidMutation
		}
		// update and store intermediate hashes for this new leaf
		// (using old inclusion proof and already updated intermediate leafs)
		fmt.Println(newLeaf)
		// the index shouldn't change:
		var index [32]byte
		copy(index[:], m.GetProof().GetLeaf().GetIndex()[:32])
		// TODO(ismail): do we actually need these copies?
		inclusionMap[index] = m.GetProof()

		updatedLeafMap[index] = &trillian.MapLeaf{
			Index: index[:],
			// LeafHash: hasher.HashLeaf(mapID, l.Index, l.LeafValue),
			LeafValue: newLeaf,
		}
		// cache proof nodes:
		for level, proof := range m.GetProof().GetInclusion() {
			sid := storage.NewNodeIDFromBigInt(level, index, hasher.BitLen())
			pid := sid.Neighbor()
			// TODO Do we need the node revision or is this only used internally?
			pNode := &storage.Node{
				NodeID:       pid,
				Hash:         proof,
				NodeRevision: 0,
			}
			if p, ok := oldProofNodes[pid.String()]; ok {
				// sanity check: for each mutation overlapping proof nodes should be
				// equal:
				bytes.Equal(p.Hash, proof)
			} else {
				oldProofNodes[pid.String()] = pNode
			}
		}
	}
	// TODO write get function that returns and potentially recomputes proof nodes
	// (if neccessary) and a set method that updates recomputed proof nodes and
	// call:
	//
	//hs2 := merkle.NewHStar2(mapID, hasher)
	//hs2.HStar2Nodes([]byte{}, hasher.Size(), new []HStar2LeafHash

	//			get SparseGetNodeFunc, set SparseSetNodeFunc)
	//
	// compute the new leaf and store the intermediate hashes locally.
	// compute the new root using local intermediate hashes from epoch e.
	// verify rootHash
	return errors.New("TODO: implement verification logic")
}
