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

	"github.com/google/key-transparency/commitments"
	tv "github.com/google/key-transparency/tree/sparse/verifier"
	"github.com/google/key-transparency/vrf"

	"github.com/golang/protobuf/proto"
	ct "github.com/google/certificate-transparency/go"

	ctmap "github.com/google/key-transparency/proto/ctmap"
	pb "github.com/google/key-transparency/proto/keytransparency_v1"
)

var (
	// ErrInvalidVRF occurs when the VRF doesn't validate.
	ErrInvalidVRF = errors.New("invalid VRF")
	// ErrInvalidSparseProof occurs when the sparse merkle proof for the map doesn't validate.
	ErrInvalidSparseProof = errors.New("invalid sparse proof")
)

// VerifyCommitment verifies that the commitment in `in` is correct for userID.
func VerifyCommitment(userID string, in *pb.GetEntryResponse) error {
	if in.Committed != nil {
		entry := new(pb.Entry)
		if err := proto.Unmarshal(in.GetLeafProof().LeafData, entry); err != nil {
			return err
		}
		if err := commitments.VerifyName(userID, entry.Commitment, in.Committed); err != nil {
			return err
		}
	}
	return nil
}

// VerifyVRF verifies that the VRF and proof in `in` is correct for userID.
func VerifyVRF(userID string, in *pb.GetEntryResponse, vrf vrf.PublicKey) ([32]byte, error) {
	if !vrf.Verify([]byte(userID), in.Vrf, in.VrfProof) {
		return [32]byte{}, ErrInvalidVRF
	}
	return vrf.Index(in.Vrf), nil
}

// VerifyLeafProof returns true if the neighbor hashes and entry chain up to the
// expectedRoot.
func VerifyLeafProof(index []byte, leafproof *ctmap.GetLeafResponse,
	smh *ctmap.SignedMapHead, treeVrf *tv.Verifier) error {
	if err := treeVrf.VerifyProof(leafproof.Neighbors, index, leafproof.LeafData, smh.MapHead.Root); err != nil {
		return ErrInvalidSparseProof
	}
	return nil
}

// VerifySMH verifies that the Signed Map Head is correctly signed.
func (c *Client) VerifySMH(smh *ctmap.SignedMapHead) error {
	return c.verifier.Verify(smh.GetMapHead(), smh.Signatures[c.verifier.KeyName])
}

func (c *Client) verifyGetEntryResponse(userID string, in *pb.GetEntryResponse) error {
	if err := VerifyCommitment(userID, in); err != nil {
		return err
	}

	index, err := VerifyVRF(userID, in, c.vrf)
	if err != nil {
		return err
	}

	if err := VerifyLeafProof(index[:], in.GetLeafProof(), in.GetSmh(), c.treeVrf); err != nil {
		return err
	}

	if err := c.VerifySMH(in.GetSmh()); err != nil {
		return err
	}
	return nil
}

// verifyLog checks the expected root against the log of signed map heads.
func (c *Client) verifyLog(smh *ctmap.SignedMapHead, sctBytes []byte) error {
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
	hash := ct.JSONV1LeafHash(sct, smh)
	_, err = c.ctlog.GetProofByHash(hash, sth.TreeSize)
	if err != nil {
		return err
	}
	// TODO: Verify inclusion proof.

	return nil
}
