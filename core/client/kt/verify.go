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
	"context"
	"errors"
	"io/ioutil"
	"log"

	"github.com/google/key-transparency/core/client/ctlog"
	"github.com/google/key-transparency/core/commitments"
	"github.com/google/key-transparency/core/signatures"
	"github.com/google/key-transparency/core/tree/sparse"
	tv "github.com/google/key-transparency/core/tree/sparse/verifier"
	"github.com/google/key-transparency/core/vrf"

	"github.com/golang/protobuf/proto"
	ct "github.com/google/certificate-transparency/go"
	"github.com/google/certificate-transparency/go/tls"

	tpb "github.com/google/key-transparency/core/proto/keytransparency_v1_types"
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
	sig  signatures.Verifier
	log  ctlog.Verifier
}

// New creates a new instance of the client verifier.
func New(vrf vrf.PublicKey, tree *tv.Verifier, sig signatures.Verifier, log ctlog.Verifier) *Verifier {
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
		if err := proto.Unmarshal(in.GetLeafProof().LeafData, entry); err != nil {
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
//  - Verify SCT.
func (v *Verifier) VerifyGetEntryResponse(ctx context.Context, userID string, in *tpb.GetEntryResponse) error {
	if err := v.VerifyCommitment(userID, in); err != nil {
		Vlog.Printf("✗ Commitment verification failed.")
		return err
	}
	Vlog.Printf("✓ Commitment verified.")

	if err := v.vrf.Verify([]byte(userID), in.Vrf, in.VrfProof); err != nil {
		Vlog.Printf("✗ VRF verification failed.")
		return err
	}
	Vlog.Printf("✓ VRF verified.")
	index := v.vrf.Index(in.Vrf)

	leafProof := in.GetLeafProof()
	if leafProof == nil {
		return ErrNilProof
	}

	if err := v.tree.VerifyProof(leafProof.Neighbors, index[:], leafProof.LeafData, sparse.FromBytes(in.GetSmh().MapHead.Root)); err != nil {
		Vlog.Printf("✗ Sparse tree proof verification failed.")
		return err
	}
	Vlog.Printf("✓ Sparse tree proof verified.")

	if err := v.sig.Verify(in.GetSmh().GetMapHead(), in.GetSmh().Signatures[v.sig.KeyID()]); err != nil {
		Vlog.Printf("✗ Signed Map Head signature verification failed.")
		return err
	}
	Vlog.Printf("✓ Signed Map Head signature verified.")

	// Verify SCT.
	sct := new(ct.SignedCertificateTimestamp)
	if _, err := tls.Unmarshal(in.SmhSct, sct); err != nil {
		return err
	}
	if err := v.log.VerifySCT(ctx, in.GetSmh(), sct); err != nil {
		Vlog.Printf("✗ Signed Map Head CT inclusion proof verification failed.")
		return err
	}
	Vlog.Printf("✓ Signed Map Head CT inclusion proof verified.")
	return nil
}
