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

package kt

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/google/keytransparency/core/crypto/commitments"
	"github.com/google/keytransparency/core/crypto/vrf"

	"github.com/golang/protobuf/proto"
	"github.com/google/trillian"
	"github.com/google/trillian/client"
	tcrypto "github.com/google/trillian/crypto"
	"github.com/google/trillian/merkle"
	"github.com/google/trillian/merkle/hashers"
	"golang.org/x/net/context"

	tpb "github.com/google/keytransparency/core/proto/keytransparency_v1_types"
)

var (
	// ErrNilProof occurs when the provided GetEntryResponse contains a nil proof.
	ErrNilProof = errors.New("nil proof")

	// Vlog is the verbose logger. By default it outputs to /dev/null.
	Vlog = log.New(ioutil.Discard, "", 0)
)

// Verifier is a client helper library for verifying request and responses.
type Verifier struct {
	vrf    vrf.PublicKey
	hasher hashers.MapHasher
	sig    crypto.PublicKey
	log    client.LogVerifier
}

// New creates a new instance of the client verifier.
func New(vrf vrf.PublicKey,
	hasher hashers.MapHasher,
	sig crypto.PublicKey,
	log client.LogVerifier) *Verifier {
	return &Verifier{
		vrf:    vrf,
		hasher: hasher,
		sig:    sig,
		log:    log,
	}
}

// VerifyGetEntryResponse verifies GetEntryResponse:
//  - Verify commitment.
//  - Verify VRF.
//  - Verify tree proof.
//  - Verify signature.
//  - Verify consistency proof from log.Root().
//  - Verify inclusion proof.
func (v *Verifier) VerifyGetEntryResponse(ctx context.Context, userID, appID string,
	trusted *trillian.SignedLogRoot, in *tpb.GetEntryResponse) error {
	// Unpack the merkle tree leaf value.
	entry := new(tpb.Entry)
	if err := proto.Unmarshal(in.GetLeafProof().GetLeaf().GetLeafValue(), entry); err != nil {
		return err
	}

	// If this is not a proof of absence, verify the connection between
	// profileData and the commitment in the merkle tree leaf.
	if in.GetCommitted() != nil {
		commitment := entry.GetCommitment()
		data := in.GetCommitted().GetData()
		nonce := in.GetCommitted().GetKey()
		if err := commitments.Verify(userID, appID, commitment, data, nonce); err != nil {
			Vlog.Printf("✗ Commitment verification failed.")
			return fmt.Errorf("commitments.Verify(): %v", err)
		}
	}
	Vlog.Printf("✓ Commitment verified.")

	index, err := v.vrf.ProofToHash(vrf.UniqueID(userID, appID), in.GetVrfProof())
	if err != nil {
		Vlog.Printf("✗ VRF verification failed.")
		return fmt.Errorf("vrf.ProofToHash(%v, %v): %v", userID, appID, err)
	}
	Vlog.Printf("✓ VRF verified.")

	leafProof := in.GetLeafProof()
	if leafProof == nil {
		return ErrNilProof
	}

	leaf := leafProof.GetLeaf().GetLeafValue()
	proof := leafProof.GetInclusion()
	expectedRoot := in.GetSmr().GetRootHash()
	mapID := in.GetSmr().GetMapId()
	leafHash := v.hasher.HashLeaf(mapID, index[:], leaf)
	if err := merkle.VerifyMapInclusionProof(mapID, index[:], leafHash, expectedRoot, proof, v.hasher); err != nil {
		Vlog.Printf("✗ Sparse tree proof verification failed.")
		return fmt.Errorf("VerifyMapInclusionProof(): %v", err)
	}
	Vlog.Printf("✓ Sparse tree proof verified.")

	// SignedMapRoot contains its own signature. To verify, we need to create a local
	// copy of the object and return the object to the state it was in when signed
	// by removing the signature from the object.
	smr := *in.GetSmr()
	smr.Signature = nil // Remove the signature from the object to be verified.
	if err := tcrypto.VerifyObject(v.sig, smr, in.GetSmr().GetSignature()); err != nil {
		Vlog.Printf("✗ Signed Map Head signature verification failed.")
		return fmt.Errorf("sig.Verify(SMR): %v", err)
	}
	Vlog.Printf("✓ Signed Map Head signature verified.")

	// Verify consistency proof between root and newroot.
	// TODO(gdbelvin): Gossip root.
	if err := v.log.VerifyRoot(trusted, in.GetLogRoot(), in.GetLogConsistency()); err != nil {
		return fmt.Errorf("VerifyRoot(%v, %v): %v", in.GetLogRoot(), in.GetLogConsistency(), err)
	}
	Vlog.Printf("✓ Log root updated.")

	// Verify inclusion proof.
	b, err := json.Marshal(in.GetSmr())
	if err != nil {
		return fmt.Errorf("json.Marshal(): %v", err)
	}
	if err := v.log.VerifyInclusionAtIndex(trusted, b, in.GetSmr().GetMapRevision(),
		in.GetLogInclusion()); err != nil {
		return fmt.Errorf("VerifyInclusionAtIndex(%s, %v, _): %v",
			b, in.GetSmr().GetMapRevision(), err)
	}
	Vlog.Printf("✓ Log inclusion proof verified.")
	return nil
}
