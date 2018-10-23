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

// This file contains functions that download epochs and mutations.

import (
	"context"
	"fmt"
	"time"

	"github.com/golang/glog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
)

// EpochMutations contains all the mutations needed to advance
// the map from epoch-1 to epoch.
type EpochMutations struct {
	Epoch     *pb.Epoch
	Mutations []*pb.MutationProof
}

// StreamEpochs repeatedly fetches epochs and sends them to out until GetEpoch
// returns an error other than NotFound or until ctx.Done is closed.  When
// GetEpoch returns NotFound, it waits one pollPeriod before trying again.
func (c *Client) StreamEpochs(ctx context.Context, domainID string, startEpoch int64, out chan<- *pb.Epoch) error {
	defer close(out)
	wait := time.NewTicker(c.RetryDelay).C
	for i := startEpoch; ; {
		// time out if we exceed the poll period:
		epoch, err := c.cli.GetEpoch(ctx, &pb.GetEpochRequest{
			DomainId:      domainID,
			Epoch:         i,
			FirstTreeSize: startEpoch,
		})
		// If this epoch was not found, wait and retry.
		if s, _ := status.FromError(err); s.Code() == codes.NotFound {
			glog.Infof("Waiting for a new epoch to appear")
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-wait:
				continue
			}
		} else if err != nil {
			glog.Warningf("GetEpoch(%v,%v): %v", domainID, i, err)
			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case out <- epoch:
			i++
		}
	}
}

// EpochMutations fetches all the mutations in an epoch
func (c *Client) EpochMutations(ctx context.Context, epoch *pb.Epoch) ([]*pb.MutationProof, error) {
	mapRoot, err := c.VerifySignedMapRoot(epoch.GetMapRoot())
	if err != nil {
		return nil, err
	}
	mutations := []*pb.MutationProof{}
	token := ""
	for {
		resp, err := c.cli.ListMutations(ctx, &pb.ListMutationsRequest{
			DomainId:  epoch.GetDomainId(),
			Epoch:     int64(mapRoot.Revision),
			PageToken: token,
		})
		if err != nil {
			return nil, fmt.Errorf("GetMutations(%v): %v", epoch.GetDomainId(), err)
		}
		mutations = append(mutations, resp.GetMutations()...)
		token = resp.GetNextPageToken()
		if token == "" {
			break
		}
	}
	return mutations, nil
}
