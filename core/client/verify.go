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
	"bytes"
	"errors"
	"fmt"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"github.com/google/trillian/types"
	"github.com/kr/pretty"

	"github.com/google/keytransparency/core/crypto/commitments"
	"github.com/google/keytransparency/core/crypto/vrf"
	"github.com/google/keytransparency/core/crypto/vrf/p256"
	"github.com/google/keytransparency/core/mutator/entry"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	tclient "github.com/google/trillian/client"
	_ "github.com/google/trillian/merkle/coniks"  // Register hasher
	_ "github.com/google/trillian/merkle/rfc6962" // Register hasher
)

var (
	// ErrNilProof occurs when the provided GetUserResponse contains a nil proof.
	ErrNilProof = errors.New("nil proof")
)

// RealVerifier is a client helper library for verifying request and responses.
// Implements Verifier.
type RealVerifier struct {
	vrf vrf.PublicKey
	*tclient.MapVerifier
	*tclient.LogVerifier
}

// NewVerifier creates a new instance of the client verifier.
func NewVerifier(vrf vrf.PublicKey,
	mapVerifier *tclient.MapVerifier,
	logVerifier *tclient.LogVerifier) *RealVerifier {
	return &RealVerifier{
		vrf:         vrf,
		MapVerifier: mapVerifier,
		LogVerifier: logVerifier,
	}
}

// NewVerifierFromDirectory creates a new instance of the client verifier from a config.
func NewVerifierFromDirectory(config *pb.Directory) (*RealVerifier, error) {
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
func (v *RealVerifier) Index(vrfProof []byte, directoryID, userID string) ([]byte, error) {
	index, err := v.vrf.ProofToHash([]byte(userID), vrfProof)
	if err != nil {
		return nil, fmt.Errorf("vrf.ProofToHash(): %v", err)
	}
	return index[:], nil
}

// VerifyMapLeaf verifies pb.MapLeaf:
//  - Verify commitment.
//  - Verify VRF and index.
//  - Verify map inclusion proof.
func (v *RealVerifier) VerifyMapLeaf(directoryID, userID string,
	in *pb.MapLeaf, mapRoot *types.MapRootV1) error {
	glog.V(5).Infof("VerifyMapLeaf(%v/%v): %# v", directoryID, userID, pretty.Formatter(in))

	// Unpack the merkle tree leaf value.
	leafValue := in.GetMapInclusion().GetLeaf().GetLeafValue()
	signed, err := entry.FromLeafValue(leafValue)
	if err != nil {
		return err
	}
	var e pb.Entry
	if err := proto.Unmarshal(signed.GetEntry(), &e); err != nil {
		return err
	}

	// If this is not a proof of absence, verify the connection between
	// profileData and the commitment in the merkle tree leaf.
	if in.GetCommitted() != nil {
		commitment := e.GetCommitment()
		data := in.GetCommitted().GetData()
		nonce := in.GetCommitted().GetKey()
		if err := commitments.Verify(userID, commitment, data, nonce); err != nil {
			Vlog.Printf("✗ Commitment verification failed.")
			return fmt.Errorf("commitments.Verify(%v, %x, %x, %v): %v", userID, commitment, data, nonce, err)
		}
	}
	Vlog.Printf("✓ Commitment verified.")

	index, err := v.Index(in.GetVrfProof(), directoryID, userID)
	if err != nil {
		Vlog.Printf("✗ VRF verification failed.")
		return err
	}

	if leafValue != nil && !bytes.Equal(index, e.Index) {
		Vlog.Printf("✗ VRF verification failed.")
		return fmt.Errorf("Entry.Index: %x, want %x", e.Index, index)
	}
	Vlog.Printf("✓ VRF verified.")

	leafProof := in.GetMapInclusion()
	if leafProof == nil {
		return ErrNilProof
	}
	leafProof.Leaf.Index = index

	if err := v.VerifyMapLeafInclusionHash(mapRoot.RootHash, leafProof); err != nil {
		Vlog.Printf("✗ Sparse tree proof verification failed.")
		return fmt.Errorf("VerifyMapLeafInclusion(): %v", err)
	}
	Vlog.Printf("✓ Sparse tree proof verified.")
	return nil
}

// VerifyRevision verifies that revision is correctly signed and included in the append only log.
// VerifyRevision also verifies that revision.LogRoot is consistent with the last trusted SignedLogRoot.
func (v *RealVerifier) VerifyRevision(in *pb.Revision, trusted types.LogRootV1) (*types.LogRootV1, *types.MapRootV1, error) {
	mapRoot, err := v.VerifySignedMapRoot(in.GetMapRoot().GetMapRoot())
	if err != nil {
		Vlog.Printf("✗ Signed Map Head signature verification failed.")
		return nil, nil, fmt.Errorf("VerifySignedMapRoot(): %v", err)
	}

	Vlog.Printf("✓ Signed Map Head signature verified.")

	// Verify consistency proof between root and newroot.
	// TODO(gdbelvin): Gossip root.
	logRoot, err := v.VerifyRoot(&trusted,
		in.GetLatestLogRoot().GetLogRoot(),
		in.GetLatestLogRoot().GetLogConsistency())
	if err != nil {
		return nil, nil, fmt.Errorf("logVerifier: VerifyRoot(%v -> %v, %v): %v",
			trusted, in.GetLatestLogRoot(), in.GetLatestLogRoot().GetLogConsistency(), err)
	}

	// Verify inclusion proof.
	b := in.GetMapRoot().GetMapRoot().GetMapRoot()
	leafIndex := int64(mapRoot.Revision)
	if err := v.VerifyInclusionAtIndex(logRoot, b, leafIndex, in.GetMapRoot().GetLogInclusion()); err != nil {
		return nil, nil, fmt.Errorf("logVerifier: VerifyInclusionAtIndex(%x, %v, _): %v", b, leafIndex, err)
	}
	Vlog.Printf("✓ Log inclusion proof verified.")
	return logRoot, mapRoot, nil
}
