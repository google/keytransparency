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
// reconstruct clients can query.
package monitor

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"github.com/golang/glog"

	"github.com/google/trillian/merkle"
	"github.com/google/trillian/merkle/coniks"
	"github.com/google/trillian/storage"

	tcrypto "github.com/google/trillian/crypto"

	"github.com/google/keytransparency/core/mutator/entry"
	ktpb "github.com/google/keytransparency/core/proto/keytransparency_v1_types"
	mopb "github.com/google/keytransparency/core/proto/monitor_v1_types"
	"time"
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
func (m *Monitor) VerifyResponse(in *ktpb.GetMutationsResponse, allMuts []*ktpb.Mutation) *mopb.GetMonitoringResponse {
	resp := new(mopb.GetMonitoringResponse)
	seen := time.Now().UnixNano()
	resp.SeenTimestampNanos = seen

	// copy of received SMR:
	smr := *in.Smr
	resp.Smr = &smr
	// reset map
	resp.Smr.Signature = nil

	// verify signature on map root:
	if err := tcrypto.VerifyObject(m.mapPubKey, resp.Smr, in.GetSmr().GetSignature()); err != nil {
		glog.Errorf("couldn't verify signature on map root: %v", err)
		resp.InvalidMapSigProof = in.GetSmr()
	}

	logRoot :=  in.GetLogRoot()
	// Verify SignedLogRoot signature.
	hash := tcrypto.HashLogRoot(*logRoot)
	if err := tcrypto.Verify(m.logPubKey, hash, logRoot.GetSignature()); err != nil {
		resp.InvalidLogSigProof = logRoot
	}

	// Implicitly trust the first root we get.
	if m.trusted.TreeSize != 0 {
		// Verify consistency proof.
		if err := m.logVerifier.VerifyConsistencyProof(
			m.trusted.TreeSize, logRoot.TreeSize,
			m.trusted.RootHash, logRoot.RootHash,
			in.GetLogConsistency()); err != nil {
			// TODO
		}
	}

	// TODO:
	// logVerifier.VerifyInclusionProof()

	if err := verifyMutations(allMuts, in.GetSmr().GetRootHash(), in.GetSmr().GetMapId()); err != nil {
		// TODO resp.InvalidMutation
	}

	return resp
}

func verifyMutations(muts []*ktpb.Mutation, expectedRoot []byte, mapID int64) error {
	newLeaves := make([]merkle.HStar2LeafHash, 0, len(muts))
	mutator := entry.New()
	oldProofNodes := make(map[string][]byte)
	hasher := coniks.Default

	for _, m := range muts {
		// verify that the provided leaf’s inclusion proof goes to epoch e-1:
		//if err := merkle.VerifyMapInclusionProof(mapID, index,
		//	leafHash, rootHash, proof, hasher); err != nil {
		//	glog.Errorf("VerifyMapInclusionProof(%x): %v", index, err)
		//	// TODO modify response object
		//}
		oldLeaf, err := entry.FromLeafValue(m.GetProof().GetLeaf().GetLeafValue())
		if err != nil {
			return ErrInvalidMutation
		}

		// compute the new leaf
		newLeaf, err := mutator.Mutate(oldLeaf, m.GetUpdate())
		if err != nil {
			// TODO(ismail): collect all data to reproduce this (expectedRoot, oldLeaf, and mutation)
			return ErrInvalidMutation
		}
		index := m.GetProof().GetLeaf().GetIndex()
		newLeafnID := storage.NewNodeIDFromPrefixSuffix(index, storage.Suffix{}, hasher.BitLen())
		newLeafHash := hasher.HashLeaf(mapID, index, newLeaf)
		newLeaves = append(newLeaves, merkle.HStar2LeafHash{
			Index:    newLeafnID.BigInt(),
			LeafHash: newLeafHash,
		})
		// store the proof hashes locally to recompute the tree below:
		sibIDs := newLeafnID.Siblings()
		for level, proof := range m.GetProof().GetInclusion() {
			pID := sibIDs[level]
			if p, ok := oldProofNodes[pID.String()]; ok {
				// sanity check: for each mutation overlapping proof nodes should be
				// equal:
				if !bytes.Equal(p, proof) {
					// TODO: this is really odd -> monitor should complain!
				}
			} else {
				oldProofNodes[pID.String()] = proof
			}
		}
	}

	// compute the new root using local intermediate hashes from epoch e
	// (above proof hashes):
	hs2 := merkle.NewHStar2(mapID, hasher)
	newRoot, err := hs2.HStar2Nodes([]byte{}, hasher.Size(), newLeaves,
		func(depth int, index *big.Int) ([]byte, error) {
			nID := storage.NewNodeIDFromBigInt(depth, index, hasher.BitLen())
			if p, ok := oldProofNodes[nID.String()]; ok {
				return p, nil
			}
			return nil, nil
		}, nil)
	if err != nil {
		glog.Errorf("hs2.HStar2Nodes(_): %v", err)
		fmt.Errorf("could not compute new root hash: hs2.HStar2Nodes(_): %v", err)
	}
	// verify rootHash
	if !bytes.Equal(newRoot, expectedRoot) {
		return ErrNotMatchingRoot
	}
	return nil
}
