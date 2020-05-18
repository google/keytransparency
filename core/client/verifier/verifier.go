// Copyright 2019 Google Inc. All Rights Reserved.
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

package verifier

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/google/trillian/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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

// LogTracker tracks a series of consistent log roots.
type LogTracker interface {
	// LastVerifiedLogRoot retrieves the tree size of the latest log root.
	LastVerifiedLogRoot() *pb.LogRootRequest
	// VerifyLogRoot verifies root and updates the trusted root if it is newer.
	VerifyLogRoot(state *pb.LogRootRequest, newRoot *pb.LogRoot) (*types.LogRootV1, error)
}

// LogTrackerFactory allows the caller of NewFromDirectory to supply different
// tracker implementations.  eg. no-op, single-synchronous-head, and multi-head tracking.
type LogTrackerFactory func(*tclient.LogVerifier) LogTracker

// Verifier is a client helper library for verifying requests and responses.
type Verifier struct {
	vrf     vrf.PublicKey
	mv      *tclient.MapVerifier
	lv      *tclient.LogVerifier
	lt      LogTracker
	verbose *log.Logger
}

// New creates a new instance of the client verifier.
func New(vrf vrf.PublicKey,
	mv *tclient.MapVerifier,
	lv *tclient.LogVerifier,
	lt LogTracker) *Verifier {
	return &Verifier{
		vrf:     vrf,
		mv:      mv,
		lv:      lv,
		lt:      lt,
		verbose: log.New(ioutil.Discard, "", 0),
	}
}

// NewFromDirectory creates a new instance of the client verifier from a config.
func NewFromDirectory(config *pb.Directory, f LogTrackerFactory) (*Verifier, error) {
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

	tracker := f(logVerifier)

	return New(vrfPubKey, mapVerifier, logVerifier, tracker), nil
}

// Index computes the index from a VRF proof.
func (v *Verifier) Index(vrfProof []byte, directoryID, userID string) ([]byte, error) {
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
func (v *Verifier) VerifyMapLeaf(directoryID, userID string,
	in *pb.MapLeaf, mapRoot *types.MapRootV1) error {
	if mapRoot == nil {
		return status.Errorf(codes.Internal, "nil MapRoot")
	}
	glog.V(5).Infof("VerifyMapLeaf(%v/%v): %# v", directoryID, userID, in)

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
			v.verbose.Printf("✗ Commitment verification failed.")
			return fmt.Errorf("commitments.Verify(%v, %x, %x, %v): %v", userID, commitment, data, nonce, err)
		}
	}
	v.verbose.Printf("✓ Commitment verified.")

	index, err := v.Index(in.GetVrfProof(), directoryID, userID)
	if err != nil {
		v.verbose.Printf("✗ VRF verification failed.")
		return err
	}

	if leafValue != nil && !bytes.Equal(index, e.Index) {
		v.verbose.Printf("✗ VRF verification failed.")
		return fmt.Errorf("entry has wrong index: %x, want %x", e.Index, index)
	}
	v.verbose.Printf("✓ VRF verified.")

	leafProof := in.GetMapInclusion()
	if leafProof == nil {
		return ErrNilProof
	}
	leafProof.Leaf.Index = index

	if err := v.mv.VerifyMapLeafInclusionHash(mapRoot.RootHash, leafProof); err != nil {
		v.verbose.Printf("✗ Sparse tree proof verification failed.")
		return fmt.Errorf("map inclusion proof failed: %v", err)
	}
	v.verbose.Printf("✓ map inclusion proof verified.")
	return nil
}

// LastVerifiedLogRoot returns a LogRootRequest for making an RPC
func (v *Verifier) LastVerifiedLogRoot() *pb.LogRootRequest {
	return v.lt.LastVerifiedLogRoot()
}

// VerifyLogRoot verifies that revision.LogRoot is consistent with the last trusted SignedLogRoot.
func (v *Verifier) VerifyLogRoot(req *pb.LogRootRequest, slr *pb.LogRoot) (*types.LogRootV1, error) {
	// TODO(gdbelvin): Gossip root.
	return v.lt.VerifyLogRoot(req, slr)
}

// VerifyMapRevision verifies that the map revision is correctly signed and included in the append only log.
func (v *Verifier) VerifyMapRevision(lr *types.LogRootV1, smr *pb.MapRoot) (*types.MapRootV1, error) {
	mapRoot, err := v.mv.VerifySignedMapRoot(smr.GetMapRoot())
	if err != nil {
		v.verbose.Printf("✗ Signed Map Head signature verification failed.")
		return nil, err
	}
	v.verbose.Printf("✓ Signed Map Head signature verified.")

	// Verify inclusion proof.
	b := smr.GetMapRoot().GetMapRoot()
	leafIndex := int64(mapRoot.Revision)
	if err := v.lv.VerifyInclusionAtIndex(lr, b, leafIndex, smr.GetLogInclusion()); err != nil {
		return nil, fmt.Errorf("logVerifier: VerifyInclusionAtIndex(%x, %v, _): %v", b, leafIndex, err)
	}
	v.verbose.Printf("✓ Log inclusion proof verified.")
	return mapRoot, nil
}
