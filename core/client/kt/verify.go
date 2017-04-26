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

	"github.com/google/keytransparency/core/commitments"
	"github.com/google/keytransparency/core/crypto/vrf"
	"github.com/google/keytransparency/core/tree/sparse"
	tv "github.com/google/keytransparency/core/tree/sparse/verifier"

	"github.com/golang/protobuf/proto"
	"github.com/google/trillian/client"
	tcrypto "github.com/google/trillian/crypto"
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
	vrf  vrf.PublicKey
	tree *tv.Verifier
	sig  crypto.PublicKey
	log  client.VerifyingLogClient
}

// New creates a new instance of the client verifier.
func New(vrf vrf.PublicKey,
	tree *tv.Verifier,
	sig crypto.PublicKey,
	log client.VerifyingLogClient) *Verifier {
	return &Verifier{
		vrf:  vrf,
		tree: tree,
		sig:  sig,
		log:  log,
	}
}

// VerifyCommitment verifies that the commitment in `in` is correct for userID.
func (Verifier) VerifyCommitment(userID string, in *tpb.GetEntryResponse) error {
	if in.Committed != nil {
		entry := new(tpb.Entry)
		if err := proto.Unmarshal(in.GetLeafProof().GetLeaf().GetLeafValue(), entry); err != nil {
			return err
		}
		if err := commitments.Verify(userID, entry.Commitment, in.Committed); err != nil {
			return err
		}
	}
	return nil
}

// VerifyGetEntryResponse verifies GetEntryResponse:
//  - Verify commitment.
//  - Verify VRF.
//  - Verify tree proof.
//  - Verify signature.
//  - Verify inclusion proof.
func (v *Verifier) VerifyGetEntryResponse(ctx context.Context, userID string, in *tpb.GetEntryResponse) error {
	if err := v.VerifyCommitment(userID, in); err != nil {
		Vlog.Printf("✗ Commitment verification failed.")
		return fmt.Errorf("VerifyCommitment(): %v", err)
	}
	Vlog.Printf("✓ Commitment verified.")

	if err := v.vrf.Verify([]byte(userID), in.Vrf, in.VrfProof); err != nil {
		Vlog.Printf("✗ VRF verification failed.")
		return fmt.Errorf("vrf.Verify(): %v", err)
	}
	Vlog.Printf("✓ VRF verified.")
	index := v.vrf.Index(in.Vrf)

	leafProof := in.GetLeafProof()
	if leafProof == nil {
		return ErrNilProof
	}

	if err := v.tree.VerifyProof(leafProof.Inclusion, index[:], leafProof.Leaf.LeafValue, sparse.FromBytes(in.GetSmr().RootHash)); err != nil {
		Vlog.Printf("✗ Sparse tree proof verification failed.")
		return fmt.Errorf("tree.VerifyProof(): %v", err)
	}
	Vlog.Printf("✓ Sparse tree proof verified.")

	smr := *in.GetSmr()
	smr.Signature = nil // Remove the signature from the object to be verified.
	if err := tcrypto.VerifyObject(v.sig, smr, in.GetSmr().Signature); err != nil {
		Vlog.Printf("✗ Signed Map Head signature verification failed.")
		return fmt.Errorf("sig.Verify(SMR): %v", err)
	}
	Vlog.Printf("✓ Signed Map Head signature verified.")

	// Verify inclusion proof.
	b, err := json.Marshal(in.GetSmr())
	if err != nil {
		return fmt.Errorf("json.Marshal(): %v", err)
	}
	if err := v.log.VerifyInclusionAtIndex(ctx, b, in.GetSmr().GetMapRevision()); err != nil {
		return fmt.Errorf("log.VerifyInclusionAtIndex(): %v", err)
	}
	return nil
}
