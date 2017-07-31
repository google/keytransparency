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
	"errors"

	"github.com/golang/glog"

	// "github.com/google/trillian"
	// "github.com/google/trillian/merkle"

	tcrypto "github.com/google/trillian/crypto"

	ktpb "github.com/google/keytransparency/core/proto/keytransparency_v1_types"
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
	// ErrInvalidMapSignature occurs when the signature on the observed map root
	// is invalid.
	ErrInvalidLogSignature = errors.New("invalid signature on log in GetMutationsResponse")
)

// verifyResponse verifies a response received by the GetMutations API.
// Additionally to the response it takes a complete list of mutations. The list
// of received mutations may differ from those included in the initial response
// because of the max. page size.
func (s *Server) verifyResponse(resp *ktpb.GetMutationsResponse, allMuts []*ktpb.Mutation) error {
	// verify signature on map root:
	if err := tcrypto.VerifyObject(s.mapPubKey, resp.GetSmr(), resp.GetSmr().GetSignature()); err != nil {
		glog.Errorf("couldn't verify signature on map root: %v", err)
		return ErrInvalidMapSignature
	}
	// verify signature on log root:
	if err := tcrypto.VerifyObject(s.logPubKey, resp.GetSmr(), resp.GetLogRoot().GetSignature()); err != nil {
		glog.Errorf("couldn't verify signature on log root: %v", err)
		return ErrInvalidLogSignature
	}
	// TODO verify log-root:
	// VerifyRoot(trusted, newRoot *trillian.SignedLogRoot, consistency [][]byte) error
	// mapID := resp.GetSmr().GetMapId()

	// TODO: export applyMutations in CreateEpoch / signer.go?
	//
	// verify that the provided leaf’s inclusion proof goes to epoch e-1.
	//
	// for each mutation:
	//if err := merkle.VerifyMapInclusionProof(mapID, index,
	//	leafHash, rootHash, proof, hasher); err != nil {
	//	glog.Errorf("VerifyMapInclusionProof(%x): %v", index, err)
	//	return ErrInvalidMutation
	//}

	// verify the mutation’s validity against the previous leaf.

	// compute the new leaf and store the intermediate hashes locally.
	// compute the new root using local intermediate hashes from epoch e.
	// verify rootHash

	return errors.New("TODO: implement verification logic")
}
