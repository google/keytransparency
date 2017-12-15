// Copyright 2017 Google Inc. All Rights Reserved.
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

package mutationclient

//
// This file contains Monitor'c grpc client logic: poll mutations from the
// kt-server mutations API and page if necessary.
//

import (
	"context"
	"fmt"
	"time"

	"github.com/golang/glog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_proto"
)

// Each page contains pageSize profiles. Each profile contains multiple
// keys. Assuming 2 keys per profile (each of size 2048-bit), a page of
// size 16 will contain about 8KB of data.
const pageSize = 16

// Client queries the server side mutations API.
type Client struct {
	client     pb.KeyTransparencyServiceClient
	pollPeriod time.Duration
}

// EpochMutations contains all the mutations needed to advance
// the map from epoch-1 to epoch.
type EpochMutations struct {
	Epoch     *pb.Epoch
	Mutations []*pb.MutationProof
}

// New initializes a new mutations API monitoring client.
func New(client pb.KeyTransparencyServiceClient, pollPeriod time.Duration) *Client {
	return &Client{
		client:     client,
		pollPeriod: pollPeriod,
	}
}

// StreamEpochs repeatedly fetches epochs and sends them to out until GetEpoch
// returns an error other than NotFound or until ctx.Done is closed.  When
// GetEpoch returns NotFound, it waits one pollPeriod before trying again.
func (c *Client) StreamEpochs(ctx context.Context, domainID string, startEpoch int64, out chan<- *pb.Epoch) error {
	defer close(out)
	wait := time.NewTicker(c.pollPeriod).C
	for i := startEpoch; ; {
		// time out if we exceed the poll period:
		epoch, err := c.client.GetEpoch(ctx, &pb.GetEpochRequest{
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
	mutations := []*pb.MutationProof{}
	token := ""
	for {
		resp, err := c.client.ListMutations(ctx, &pb.ListMutationsRequest{
			DomainId:  epoch.GetDomainId(),
			Epoch:     epoch.GetSmr().GetMapRevision(),
			PageSize:  pageSize,
			PageToken: token,
		})
		if err != nil {
			return nil, fmt.Errorf("GetMutations(%v, %v): %v", epoch.GetDomainId(), pageSize, err)
		}
		mutations = append(mutations, resp.GetMutations()...)
		token = resp.GetNextPageToken()
		if token == "" {
			break
		}
	}
	return mutations, nil
}
