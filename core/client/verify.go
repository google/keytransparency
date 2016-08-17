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
	"errors"

	"github.com/google/key-transparency/core/commitments"

	"github.com/golang/protobuf/proto"

	"github.com/google/key-transparency/core/proto/ctmap"
	pb "github.com/google/key-transparency/core/proto/keytransparency_v1"
)

// ErrNilProof occurs when the provided GetEntryResponse contains a nil proof.
var ErrNilProof = errors.New("nil proof")

// VerifyCommitment verifies that the commitment in `in` is correct for userID.
func VerifyCommitment(userID string, in *pb.GetEntryResponse) error {
	if in.Committed != nil {
		entry := new(pb.Entry)
		if err := proto.Unmarshal(in.GetLeafProof().LeafData, entry); err != nil {
			return err
		}
		if err := commitments.Verify(userID, entry.Commitment, in.Committed); err != nil {
			return err
		}
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

	if err := c.vrf.Verify([]byte(userID), in.Vrf, in.VrfProof); err != nil {
		return err
	}
	index := c.vrf.Index(in.Vrf)

	leafProof := in.GetLeafProof()
	if leafProof == nil {
		return ErrNilProof
	}

	if err := c.treeVerifier.VerifyProof(leafProof.Neighbors, index[:], leafProof.LeafData, in.GetSmh().MapHead.Root); err != nil {
		return err
	}

	if err := c.VerifySMH(in.GetSmh()); err != nil {
		return err
	}
	return nil
}
