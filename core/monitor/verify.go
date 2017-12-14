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
	"encoding/json"
	"errors"
	"math/big"

	"github.com/google/keytransparency/core/mutator/entry"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/golang/glog"
	"github.com/google/trillian/merkle"
	"github.com/google/trillian/storage"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_proto"
	tcrypto "github.com/google/trillian/crypto"
	statuspb "google.golang.org/genproto/googleapis/rpc/status"
)

var (
	// ErrInconsistentProofs occurs when the server returned different hashes
	// for the same inclusion proof node in the tree.
	ErrInconsistentProofs = errors.New("inconsistent inclusion proofs")
	// ErrInvalidLogConsistencyProof occurs when the log consistency proof does
	// not verify.
	ErrInvalidLogConsistencyProof = errors.New("invalid log consistency proof")
	// ErrInvalidLogInclusion occurs if the inclusion proof for the signed map
	// root into the log does not verify.
	ErrInvalidLogInclusion = errors.New("invalid log inclusion proof")
	// ErrInvalidLogSignature occurs if the log roots signature does not verify.
	ErrInvalidLogSignature = errors.New("invalid signature on log root")
	// ErrInvalidMapSignature occurs if the map roots signature does not verify.
	ErrInvalidMapSignature = errors.New("invalid signature on map root")
	// ErrInvalidMutation occurs when verification failed because of an invalid
	// mutation.
	ErrInvalidMutation = errors.New("invalid mutation")
	// ErrNotMatchingMapRoot occurs when the reconstructed root differs from the
	// one we received from the server.
	ErrNotMatchingMapRoot = errors.New("recreated root does not match")
)

// ErrList is a list of errors.
type ErrList []error

// AppendStatus adds a status errord, or the error about adding
// the status if the latter is not nil.
func (e *ErrList) AppendStatus(s *status.Status, err error) {
	if err != nil {
		*e = append(*e, err)
	} else {
		*e = append(*e, s.Err())
	}
}

// AppendErr adds a generic error to the list.
func (e *ErrList) appendErr(err ...error) {
	*e = append(*e, err...)
}

// Proto converts all the errors to statuspb.Status.
// If the original error was not a status.Status, we use codes.Unknown.
func (e *ErrList) Proto() []*statuspb.Status {
	errs := make([]*statuspb.Status, 0, len(*e))
	for _, err := range *e {
		if s, ok := status.FromError(err); ok {
			errs = append(errs, s.Proto())
			continue
		}
		errs = append(errs, status.Newf(codes.Unknown, "%v", err).Proto())
	}
	return errs
}

// VerifyEpoch verifies a response received by the GetMutations API.
// Additionally to the response it takes a complete list of mutations. The list
// of received mutations may differ from those included in the initial response
// because of the max. page size.
func (m *Monitor) VerifyEpoch(epoch *pb.Epoch) []error {
	errs := ErrList{}

	if m.trusted == nil {
		m.trusted = epoch.GetLogRoot()
	}

	if err := m.logVerifier.VerifyRoot(m.trusted, epoch.GetLogRoot(), epoch.GetLogConsistency()); err != nil {
		// this could be one of ErrInvalidLogSignature, ErrInvalidLogConsistencyProof
		errs.AppendStatus(status.Newf(codes.DataLoss, "VerifyRoot: %v", err).WithDetails(m.trusted, epoch))
	}
	// updated trusted log root
	m.trusted = epoch.GetLogRoot()

	b, err := json.Marshal(epoch.GetSmr())
	if err != nil {
		glog.Errorf("json.Marshal(): %v", err)
		errs.AppendStatus(status.Newf(codes.DataLoss, "json.Marshal(): %v", err).WithDetails(epoch.GetSmr()))
	}
	leafIndex := epoch.GetSmr().GetMapRevision()
	treeSize := epoch.GetLogRoot().GetTreeSize()
	err = m.logVerifier.VerifyInclusionAtIndex(epoch.GetLogRoot(), b, leafIndex, epoch.GetLogInclusion())
	if err != nil {
		glog.Errorf("m.logVerifier.VerifyInclusionAtIndex((%v, %v, _): %v", leafIndex, treeSize, err)
		errs.AppendStatus(status.Newf(codes.DataLoss, "invalid log inclusion: %v", err).WithDetails(epoch))
	}

	// copy of signed map root
	smr := *epoch.GetSmr()
	// reset to the state before it was signed:
	smr.Signature = nil
	// verify signature on map root:
	if err := tcrypto.VerifyObject(m.mapPubKey, smr, epoch.GetSmr().GetSignature()); err != nil {
		glog.Infof("couldn't verify signature on map root: %v", err)
		errs.AppendStatus(status.Newf(codes.DataLoss, "invalid map signature: %v", err).WithDetails(&smr, epoch.GetSmr().GetSignature()))
	}

	return errs
}

func (m *Monitor) verifyMutations(muts []*pb.MutationProof, oldRoot, expectedNewRoot []byte, mapID int64) []error {
	errs := ErrList{}
	mutator := entry.New()
	oldProofNodes := make(map[string][]byte)
	newLeaves := make([]merkle.HStar2LeafHash, 0, len(muts))
	glog.Infof("verifyMutations() called with %v mutations.", len(muts))

	for _, mut := range muts {
		oldLeaf, err := entry.FromLeafValue(mut.GetLeafProof().GetLeaf().GetLeafValue())
		if err != nil {
			errs.AppendStatus(status.Newf(codes.DataLoss, "could not decode leaf: %v", err).WithDetails(mut.GetLeafProof().GetLeaf()))
		}

		// verify that the provided leaf’s inclusion proof goes to epoch e-1:
		index := mut.GetLeafProof().GetLeaf().GetIndex()
		leaf := mut.GetLeafProof().GetLeaf().GetLeafValue()
		if err := merkle.VerifyMapInclusionProof(mapID, index,
			leaf, oldRoot, mut.GetLeafProof().GetInclusion(), m.mapHasher); err != nil {
			glog.Infof("VerifyMapInclusionProof(%x): %v", index, err)
			errs.AppendStatus(status.Newf(codes.DataLoss, "invalid  map inclusion proof: %v", err).WithDetails(mut.GetLeafProof()))
		}

		// compute the new leaf
		newValue, err := mutator.Mutate(oldLeaf, mut.GetMutation())
		if err != nil {
			glog.Infof("Mutation did not verify: %v", err)
			errs.AppendStatus(status.Newf(codes.DataLoss, "invalid mutation: %v", err).WithDetails(mut.GetMutation()))
		}
		newLeafnID := storage.NewNodeIDFromPrefixSuffix(index, storage.Suffix{}, m.mapHasher.BitLen())
		newLeaf, err := entry.ToLeafValue(newValue)
		if err != nil {
			glog.Infof("Failed to serialize: %v", err)
			errs.AppendStatus(status.Newf(codes.DataLoss, "failed to serialize: %v", err).WithDetails(newValue))
		}

		// BUG(gdbelvin): Proto serializations are not idempotent.
		// - Upgrade the hasher to use ObjectHash.
		// - Use deep compare between the tree and the computed value.
		newLeafHash, err := m.mapHasher.HashLeaf(mapID, index, newLeaf)
		if err != nil {
			errs.appendErr(err)
		}
		newLeaves = append(newLeaves, merkle.HStar2LeafHash{
			Index:    newLeafnID.BigInt(),
			LeafHash: newLeafHash,
		})

		// store the proof hashes locally to recompute the tree below:
		sibIDs := newLeafnID.Siblings()
		proofs := mut.GetLeafProof().GetInclusion()
		for level, sibID := range sibIDs {
			proof := proofs[level]
			if p, ok := oldProofNodes[sibID.String()]; ok {
				// sanity check: for each mut overlapping proof nodes should be
				// equal:
				if !bytes.Equal(p, proof) {
					// this is really odd and should never happen
					errs.appendErr(ErrInconsistentProofs)
				}
			} else {
				if len(proof) > 0 {
					oldProofNodes[sibID.String()] = proof
				}
			}
		}
	}

	if err := m.validateMapRoot(expectedNewRoot, mapID, newLeaves, oldProofNodes); err != nil {
		errs.appendErr(err)
	}

	return errs
}

func (m *Monitor) validateMapRoot(expectedRoot []byte, mapID int64, mutatedLeaves []merkle.HStar2LeafHash, oldProofNodes map[string][]byte) error {
	// compute the new root using local intermediate hashes from epoch e
	// (above proof hashes):
	hs2 := merkle.NewHStar2(mapID, m.mapHasher)
	newRoot, err := hs2.HStar2Nodes([]byte{}, m.mapHasher.BitLen(), mutatedLeaves,
		func(depth int, index *big.Int) ([]byte, error) {
			nID := storage.NewNodeIDFromBigInt(depth, index, m.mapHasher.BitLen())
			if p, ok := oldProofNodes[nID.String()]; ok {
				return p, nil
			}
			return nil, nil
		}, nil)

	if err != nil {
		glog.Errorf("hs2.HStar2Nodes(_): %v", err)
		return ErrNotMatchingMapRoot
	}

	// verify rootHash
	if !bytes.Equal(newRoot, expectedRoot) {
		return ErrNotMatchingMapRoot
	}

	return nil
}
