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
	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
)

// VerifyGetUser verifies that the retrieved profile of userID is correct.
func (v *Verifier) VerifyGetUser(req *pb.GetUserRequest, resp *pb.GetUserResponse) error {
	lr, err := v.VerifyLogRoot(req.GetLastVerified(), resp.GetRevision().GetLatestLogRoot())
	if err != nil {
		return err
	}
	mr, err := v.VerifyMapRevision(lr, resp.Revision.GetMapRoot())
	if err != nil {
		return err
	}
	return v.VerifyMapLeaf(req.DirectoryId, req.UserId, resp.Leaf, mr)
}

// VerifyBatchGetUser verifies that the retrieved profiles are correct.
func (v *Verifier) VerifyBatchGetUser(req *pb.BatchGetUserRequest, resp *pb.BatchGetUserResponse) error {
	lr, err := v.VerifyLogRoot(req.GetLastVerified(), resp.GetRevision().GetLatestLogRoot())
	if err != nil {
		return err
	}
	mr, err := v.VerifyMapRevision(lr, resp.Revision.GetMapRoot())
	if err != nil {
		return err
	}
	for userID, leaf := range resp.MapLeavesByUserId {
		if err := v.VerifyMapLeaf(req.DirectoryId, userID, leaf, mr); err != nil {
			return err
		}
	}
	return nil
}
