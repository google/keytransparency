// Copyright 2018 Google Inc. All Rights Reserved.
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

// This file contains functions that download revisions and mutations.

import (
	"context"
	"fmt"
	"time"

	"github.com/golang/glog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
)

// RevisionMutations contains all the mutations needed to advance
// the map from revision-1 to revision.
type RevisionMutations struct {
	Revision  *pb.Revision
	Mutations []*pb.MutationProof
}

// StreamRevisions repeatedly fetches revisions and sends them to out until GetRevision
// returns an error other than NotFound or until ctx.Done is closed.  When
// GetRevision returns NotFound, it waits one pollPeriod before trying again.
func (c *Client) StreamRevisions(ctx context.Context, directoryID string, startRevision int64, out chan<- *pb.Revision) error {
	defer close(out)
	wait := time.NewTicker(c.RetryDelay).C
	for i := startRevision; ; {
		// time out if we exceed the poll period:
		revision, err := c.cli.GetRevision(ctx, &pb.GetRevisionRequest{
			DirectoryId:          directoryID,
			Revision:             i,
			LastVerifiedTreeSize: startRevision,
		})
		// If this revision was not found, wait and retry.
		if s, _ := status.FromError(err); s.Code() == codes.NotFound {
			glog.Infof("Waiting for a new revision to appear")
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-wait:
				continue
			}
		} else if err != nil {
			glog.Warningf("GetRevision(%v,%v): %v", directoryID, i, err)
			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case out <- revision:
			i++
		}
	}
}

// RevisionMutations fetches all the mutations in an revision
func (c *Client) RevisionMutations(ctx context.Context, revision *pb.Revision) ([]*pb.MutationProof, error) {
	mapRoot, err := c.VerifySignedMapRoot(revision.GetMapRoot().GetMapRoot())
	if err != nil {
		return nil, err
	}
	mutations := []*pb.MutationProof{}
	token := ""
	for {
		resp, err := c.cli.ListMutations(ctx, &pb.ListMutationsRequest{
			DirectoryId: revision.GetDirectoryId(),
			Revision:    int64(mapRoot.Revision),
			PageToken:   token,
		})
		if err != nil {
			return nil, fmt.Errorf("list mutations on %v: %v", revision.GetDirectoryId(), err)
		}
		mutations = append(mutations, resp.GetMutations()...)
		token = resp.GetNextPageToken()
		if token == "" {
			break
		}
	}
	return mutations, nil
}
