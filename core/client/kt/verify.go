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
	"bytes"
	"errors"

	"github.com/google/key-transparency/core/client/ctlog"
	"github.com/google/key-transparency/core/commitments"
	"github.com/google/key-transparency/core/signatures"
	tv "github.com/google/key-transparency/core/tree/sparse/verifier"
	"github.com/google/key-transparency/core/vrf"

	"github.com/golang/protobuf/proto"
	ct "github.com/google/certificate-transparency/go"

	tpb "github.com/google/key-transparency/core/proto/kt_types_v1"
)

// ErrNilProof occurs when the provided GetEntryResponse contains a nil proof.
var ErrNilProof = errors.New("nil proof")

// Verifier is a client helper library for verifying request and responses.
type Verifier struct {
	vrf  vrf.PublicKey
	tree *tv.Verifier
	sig  *signatures.Verifier
	log  ctlog.Verifier
}

// New creates a new instance of the client verifier.
func New(vrf vrf.PublicKey, tree *tv.Verifier, sig *signatures.Verifier, log ctlog.Verifier) *Verifier {
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
func (v *Verifier) VerifyGetEntryResponse(userID string, in *tpb.GetEntryResponse) error {
	if err := v.VerifyCommitment(userID, in); err != nil {
		return err
	}

	if err := v.vrf.Verify([]byte(userID), in.Vrf, in.VrfProof); err != nil {
		return err
	}
	index := v.vrf.Index(in.Vrf)

	leafProof := in.GetLeafProof()
	if leafProof == nil {
		return ErrNilProof
	}

	if err := v.tree.VerifyProof(leafProof.Neighbors, index[:], leafProof.LeafData, in.GetSmh().MapHead.Root); err != nil {
		return err
	}

	if err := v.sig.Verify(in.GetSmh().GetMapHead(), in.GetSmh().Signatures[v.sig.KeyName]); err != nil {
		return err
	}

	// Verify SCT.
	sct, err := ct.DeserializeSCT(bytes.NewReader(in.SmhSct))
	if err != nil {
		return err
	}
	if err := v.log.VerifySCT(in.GetSmh(), sct); err != nil {
		return err
	}
	return nil
}
