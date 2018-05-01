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
	"context"
	"errors"
	"fmt"

	"github.com/golang/glog"
	"github.com/google/keytransparency/core/crypto/commitments"
	"github.com/google/keytransparency/core/crypto/vrf"
	"github.com/google/keytransparency/core/crypto/vrf/p256"
	"github.com/google/keytransparency/core/mutator/entry"
	"github.com/google/trillian/types"
	"github.com/kr/pretty"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	tclient "github.com/google/trillian/client"
	_ "github.com/google/trillian/merkle/coniks"  // Register hasher
	_ "github.com/google/trillian/merkle/rfc6962" // Register hasher
)

var (
	// ErrNilProof occurs when the provided GetEntryResponse contains a nil proof.
	ErrNilProof = errors.New("nil proof")
)

// Verify is a client helper library for verifying request and responses.
type Verify struct {
	vrf         vrf.PublicKey
	mapVerifier *tclient.MapVerifier
	logVerifier *tclient.LogVerifier
}

// NewVerifier creates a new instance of the client verifier.
func NewVerifier(vrf vrf.PublicKey,
	mapVerifier *tclient.MapVerifier,
	logVerifier *tclient.LogVerifier) *Verify {
	return &Verify{
		vrf:         vrf,
		mapVerifier: mapVerifier,
		logVerifier: logVerifier,
	}
}

// NewVerifierFromDomain creates a new instance of the client verifier from a config.
func NewVerifierFromDomain(config *pb.Domain) (*Verify, error) {
	logVerifier, err := tclient.NewLogVerifierFromTree(config.GetLog())
	if err != nil {
		return nil, err
	}

	mapVerifier, err := tclient.NewMapVerifierFromTree(config.GetMap())
	if err != nil {
		return nil, err
	}

	// VRF key
	vrfPubKey, err := p256.NewVRFVerifierFromRawKey(config.GetVrf().GetDer())
	if err != nil {
		return nil, fmt.Errorf("error parsing vrf public key: %v", err)
	}

	return NewVerifier(vrfPubKey, mapVerifier, logVerifier), nil
}

// Index computes the index from a VRF proof.
func (v *Verify) Index(vrfProof []byte, domainID, appID, userID string) ([]byte, error) {
	index, err := v.vrf.ProofToHash(vrf.UniqueID(userID, appID), vrfProof)
	if err != nil {
		return nil, fmt.Errorf("vrf.ProofToHash(): %v", err)
	}
	return index[:], nil
}

// VerifyGetEntryResponse verifies GetEntryResponse:
//  - Verify commitment.
//  - Verify VRF.
//  - Verify tree proof.
//  - Verify signature.
//  - Verify consistency proof from log.Root().
//  - Verify inclusion proof.
// Returns the verified map root and log root.
func (v *Verify) VerifyGetEntryResponse(ctx context.Context, domainID, appID, userID string,
	trusted types.LogRootV1, in *pb.GetEntryResponse) (*types.MapRootV1, *types.LogRootV1, error) {
	glog.V(5).Infof("VerifyGetEntryResponse(%v/%v/%v): %# v", domainID, appID, userID, pretty.Formatter(in))

	// Unpack the merkle tree leaf value.
	e, err := entry.FromLeafValue(in.GetLeafProof().GetLeaf().GetLeafValue())
	if err != nil {
		return nil, nil, err
	}

	// If this is not a proof of absence, verify the connection between
	// profileData and the commitment in the merkle tree leaf.
	if in.GetCommitted() != nil {
		commitment := e.GetCommitment()
		data := in.GetCommitted().GetData()
		nonce := in.GetCommitted().GetKey()
		if err := commitments.Verify(userID, appID, commitment, data, nonce); err != nil {
			Vlog.Printf("✗ Commitment verification failed.")
			return nil, nil, fmt.Errorf("commitments.Verify(%v, %v, %v, %v, %v): %v", userID, appID, commitment, data, nonce, err)
		}
	}
	Vlog.Printf("✓ Commitment verified.")

	index, err := v.Index(in.GetVrfProof(), domainID, appID, userID)
	if err != nil {
		Vlog.Printf("✗ VRF verification failed.")
		return nil, nil, err
	}
	Vlog.Printf("✓ VRF verified.")

	leafProof := in.GetLeafProof()
	if leafProof.GetLeaf() == nil {
		return nil, nil, ErrNilProof
	}
	leafProof.Leaf.Index = index[:]

	if err := v.mapVerifier.VerifyMapLeafInclusion(in.GetSmr(), leafProof); err != nil {
		Vlog.Printf("✗ Sparse tree proof verification failed.")
		return nil, nil, fmt.Errorf("VerifyMapLeafInclusion(): %v", err)
	}
	Vlog.Printf("✓ Sparse tree proof verified.")

	epoch := &pb.Epoch{
		Smr:            in.GetSmr(),
		LogRoot:        in.GetLogRoot(),
		LogConsistency: in.GetLogConsistency(),
		LogInclusion:   in.GetLogInclusion(),
	}
	logRoot, mapRoot, err := v.VerifyEpoch(epoch, trusted)
	if err != nil {
		return nil, nil, err
	}
	return mapRoot, logRoot, nil
}

// VerifyEpoch verifies that epoch is correctly signed and included in the append only log.
// VerifyEpoch also verifies that epoch.LogRoot is consistent with the last trusted SignedLogRoot.
func (v *Verify) VerifyEpoch(in *pb.Epoch, trusted types.LogRootV1) (*types.LogRootV1, *types.MapRootV1, error) {
	mapRoot, err := v.mapVerifier.VerifySignedMapRoot(in.GetSmr())
	if err != nil {
		Vlog.Printf("✗ Signed Map Head signature verification failed.")
		return nil, nil, fmt.Errorf("VerifySignedMapRoot(): %v", err)
	}

	Vlog.Printf("✓ Signed Map Head signature verified.")

	// Verify consistency proof between root and newroot.
	// TODO(gdbelvin): Gossip root.
	logRoot, err := v.logVerifier.VerifyRoot(&trusted, in.GetLogRoot(), in.GetLogConsistency())
	if err != nil {
		return nil, nil, fmt.Errorf("logVerifier: VerifyRoot(%v -> %v, %v): %v", trusted, in.GetLogRoot(), in.GetLogConsistency(), err)
	}

	// Verify inclusion proof.
	b := in.GetSmr().GetMapRoot()
	leafIndex := int64(mapRoot.Revision)
	if err := v.logVerifier.VerifyInclusionAtIndex(logRoot, b, leafIndex, in.GetLogInclusion()); err != nil {
		return nil, nil, fmt.Errorf("logVerifier: VerifyInclusionAtIndex(%s, %v, _): %v", b, leafIndex, err)
	}
	Vlog.Printf("✓ Log inclusion proof verified.")
	return logRoot, mapRoot, nil
}
