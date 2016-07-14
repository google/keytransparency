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
	"log"

	"github.com/google/e2e-key-server/commitments"
	"github.com/google/e2e-key-server/tree"
	"github.com/google/e2e-key-server/vrf"

	ct "github.com/google/certificate-transparency/go"
	"github.com/golang/protobuf/proto"

	ctmap "github.com/google/e2e-key-server/proto/security_ctmap"
	pb "github.com/google/e2e-key-server/proto/security_e2ekeys_v1"
)

var (
	// ErrInvalidCommitment occurs when the commitment doesn't match the profile.
	ErrInvalidCommitment = errors.New("Invalid Commitment")
	// ErrInvalidVRF occurs when the VRF doesn't validate.
	ErrInvalidVRF = errors.New("Invalid VRF")
	// ErrInvalidSparseProof occurs when the sparse merkle proof for the map doesn't validate.
	ErrInvalidSparseProof = errors.New("Invalid Sparse Proof")
)

// VerifyCommitment verifies that the commitment in `in` is correct for userID.
func VerifyCommitment(userID string, in *pb.GetEntryResponse) bool {
	if in.Profile != nil {
		entry := new(pb.Entry)
		if err := proto.Unmarshal(in.GetLeafProof().LeafData, entry); err != nil {
			log.Printf("Error unmarshaling entry: %v", err)
			return false
		}
		if err := commitments.VerifyName(userID, in.CommitmentKey, in.Profile, entry.Commitment); err != nil {
			log.Printf("Invalid profile commitment.")
			return false
		}
	}
	return true
}

// VerifyVRF verifies that the VRF and proof in `in` is correct for userID.
func VerifyVRF(userID string, in *pb.GetEntryResponse, vrf vrf.PublicKey) ([32]byte, bool) {
	if !vrf.Verify([]byte(userID), in.Vrf, in.VrfProof) {
		log.Printf("Vrf verification failed.")
		return [32]byte{}, false
	}
	return vrf.Index(in.Vrf), true
}

// VerifyLeafProof returns true if the neighbor hashes and entry chain up to the expectedRoot.
func VerifyLeafProof(index []byte, leafproof *ctmap.GetLeafResponse, seh *ctmap.SignedEpochHead, factory tree.SparseFactory) bool {
	m := factory.FromNeighbors(leafproof.Neighbors, index, leafproof.LeafData)
	calculatedRoot, err := m.ReadRoot(nil)
	if err != nil {
		log.Printf("VerifyLeafProof failed to read root: %v", err)
		return false
	}
	return bytes.Equal(seh.EpochHead.Root, calculatedRoot)
}

// VerifySEH verifies that the Signed Epoch Head is correctly signed.
func (c *Client) VerifySEH(seh *ctmap.SignedEpochHead) error {
	return c.verifier.Verify(seh.GetEpochHead(), seh.Signatures[c.verifier.KeyName])
}

func (c *Client) verifyGetEntryResponse(userID string, in *pb.GetEntryResponse) error {
	if !VerifyCommitment(userID, in) {
		return ErrInvalidCommitment
	}

	index, ok := VerifyVRF(userID, in, c.vrf)
	if !ok {
		return ErrInvalidVRF
	}

	if !VerifyLeafProof(index[:], in.GetLeafProof(), in.GetSeh(), c.factory) {
		return ErrInvalidSparseProof
	}

	if err := c.VerifySEH(in.GetSeh()); err != nil {
		return err
	}
	return nil
}

// verifyEpoch checks the expected root against the log of signed epoch heads.
func (c *Client) verifyLog(seh *ctmap.SignedEpochHead, sctBytes []byte) error {
	// 1) GetSTH.
	sth, err := c.ctlog.GetSTH()
	if err != nil {
		return err
	}
	// TODO: Verify STH signatures.

	// 2) TODO: Consistency proof
	// TODO: Advance trusted STH

	// 3) Inclusion Proof.

	// GetByHash
	sct, err := ct.DeserializeSCT(bytes.NewReader(sctBytes))
	if err != nil {
		return err
	}
	hash := ct.JSONV1LeafHash(sct, seh)
	_, err = c.ctlog.GetProofByHash(hash, sth.TreeSize)
	if err != nil {
		return err
	}
	// TODO: Verify inclusion proof.

	return nil
}
