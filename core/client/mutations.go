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
	"github.com/google/trillian/types"
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

// StreamRevisions repeatedly fetches revisions and sends them to out until
// GetRevision returns an error other than NotFound or until ctx.Done is
// closed.  When GetRevision returns NotFound, it waits one pollPeriod before
// trying again.
func (c *Client) StreamRevisions(ctx context.Context, startRevision int64, out chan<- *types.MapRootV1) error {
	defer close(out)
	wait := time.NewTicker(c.RetryDelay)
	defer wait.Stop()
	for i := startRevision; ; {
		mr, err := c.VerifiedGetRevision(ctx, i)

		// If this revision was not found, wait and retry.
		if s, _ := status.FromError(err); s.Code() == codes.NotFound {
			glog.Infof("Waiting for a new revision to appear")
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-wait.C:
				continue
			}
		} else if err != nil {
			glog.Warningf("GetRevision(%v): %v", i, err)
			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case out <- mr:
			i++
		}
	}
}

// RevisionMutations fetches all the mutations in an revision
func (c *Client) RevisionMutations(ctx context.Context, mapRoot *types.MapRootV1) ([]*pb.MutationProof, error) {
	mutations := []*pb.MutationProof{}
	token := ""
	for {
		resp, err := c.cli.ListMutations(ctx, &pb.ListMutationsRequest{
			DirectoryId: c.DirectoryID,
			Revision:    int64(mapRoot.Revision),
			PageToken:   token,
		})
		if err != nil {
			return nil, fmt.Errorf("list mutations on %v: %v", c.DirectoryID, err)
		}
		mutations = append(mutations, resp.GetMutations()...)
		token = resp.GetNextPageToken()
		if token == "" {
			break
		}
	}
	return mutations, nil
}
