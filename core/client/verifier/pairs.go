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
	"github.com/google/trillian/types"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
)

func (v *Verifier) VerifyGetUser(trusted types.LogRootV1, req *pb.GetUserRequest, resp *pb.GetUserResponse) error {
	_, smr, err := v.VerifyRevision(resp.GetRevision(), trusted)
	if err != nil {
		return err
	}
	if err := v.VerifyMapLeaf(req.GetDirectoryId(), req.GetUserId(), resp.GetLeaf(), smr); err != nil {
		return err
	}
	return nil
}

func (v *Verifier) VerifyBatchGetUser(trusted types.LogRootV1, req *pb.BatchGetUserRequest, resp *pb.BatchGetUserResponse) error {
	_, smr, err := v.VerifyRevision(resp.Revision, trusted)
	if err != nil {
		return err
	}
	for userID, leaf := range resp.MapLeavesByUserId {
		if err := v.VerifyMapLeaf(req.DirectoryId, userID, leaf, smr); err != nil {
			return err
		}
	}
	return nil

}
