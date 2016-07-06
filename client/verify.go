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
	"log"

	"github.com/google/e2e-key-server/commitments"
	"github.com/google/e2e-key-server/tree"
	"github.com/google/e2e-key-server/vrf"

	ct "github.com/google/certificate-transparency/go"
	"github.com/golang/protobuf/proto"

	ctmap "github.com/google/e2e-key-server/proto/security_ctmap"
	pb "github.com/google/e2e-key-server/proto/security_e2ekeys"
)

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
	calculatedRoot, _ := m.ReadRoot(nil)
	eh, err := EpochHead(seh)
	if err != nil {
		return false
	}
	return bytes.Equal(eh.Root, calculatedRoot)
}

func VerifySEH(seh *ctmap.SignedEpochHead) bool {
	// TODO: Verify STH signatures
	return true
}

func (c *Client) verifyGetEntryResponse(userID string, in *pb.GetEntryResponse) bool {
	if !VerifyCommitment(userID, in) {
		return false
	}

	index, ok := VerifyVRF(userID, in, c.vrf)
	if !ok {
		return false
	}

	if !VerifyLeafProof(index[:], in.GetLeafProof(), in.GetSeh(), c.factory) {
		return false
	}

	if !VerifySEH(in.GetSeh()) {
		return false
	}
	return true
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
