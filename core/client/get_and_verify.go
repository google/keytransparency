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

import (
	"context"
	"fmt"

	"github.com/golang/glog"
	"github.com/google/trillian/types"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
)

// VerifiedGetEntry fetches and verifies the results of GetEntry.
func (c *Client) VerifiedGetEntry(ctx context.Context, appID, userID string) (*pb.GetEntryResponse, *types.LogRootV1, error) {
	e, err := c.cli.GetEntry(ctx, &pb.GetEntryRequest{
		DomainId:      c.domainID,
		UserId:        userID,
		AppId:         appID,
		FirstTreeSize: int64(c.trusted.TreeSize),
	})
	if err != nil {
		return nil, nil, err
	}

	_, slr, err := c.VerifyGetEntryResponse(ctx, c.domainID, appID, userID, c.trusted, e)
	if err != nil {
		return nil, nil, err
	}
	c.updateTrusted(slr)
	glog.Infof("VerifiedGetEntry: Trusted root updated to TreeSize %v", c.trusted.TreeSize)
	Vlog.Printf("✓ Log root updated.")

	return e, slr, nil
}

// VerifiedGetLatestEpoch fetches the latest revision from the key server.
// It also verifies the consistency from the last seen revision.
// Returns the latest log root and the latest map root.
func (c *Client) VerifiedGetLatestEpoch(ctx context.Context) (*types.LogRootV1, *types.MapRootV1, error) {
	// Only one method should attempt to update the trusted root at time.
	c.trustedLock.Lock()
	defer c.trustedLock.Unlock()

	e, err := c.cli.GetLatestEpoch(ctx, &pb.GetLatestEpochRequest{
		DomainId:      c.domainID,
		FirstTreeSize: int64(c.trusted.TreeSize),
	})
	if err != nil {
		return nil, nil, err
	}

	slr, smr, err := c.VerifyEpoch(e, c.trusted)
	if err != nil {
		return nil, nil, err
	}

	// Also check that the map revision returned is the latest one.
	// TreeSize -1 == mapRoot.Revision.
	wantRevision, err := mapRevisionFor(slr)
	if err != nil {
		return nil, nil, err
	}
	if smr.Revision != wantRevision {
		return nil, nil, fmt.Errorf("GetLatestEpoch() did not return latest map revision. Got MapRoot.Revison: %v, want: %v", smr.Revision, wantRevision)
	}

	c.updateTrusted(slr)
	glog.Infof("VerifiedGetEntry: Trusted root updated to TreeSize %v", c.trusted.TreeSize)
	Vlog.Printf("✓ Log root updated.")
	return slr, smr, nil
}

// VerifiedGetEpoch fetches the requested revision from the key server.
// It also verifies the consistency of the latest log root against the last seen log root.
// Returns the latest log root and the requested map root.
func (c *Client) VerifiedGetEpoch(ctx context.Context, epoch int64) (*types.LogRootV1, *types.MapRootV1, error) {
	// Only one method should attempt to update the trusted root at time.
	c.trustedLock.Lock()
	defer c.trustedLock.Unlock()

	e, err := c.cli.GetEpoch(ctx, &pb.GetEpochRequest{
		DomainId:      c.domainID,
		Epoch:         epoch,
		FirstTreeSize: int64(c.trusted.TreeSize),
	})
	if err != nil {
		return nil, nil, err
	}

	slr, smr, err := c.VerifyEpoch(e, c.trusted)
	if err != nil {
		return nil, nil, err
	}

	c.updateTrusted(slr)
	glog.Infof("VerifiedGetEntry: Trusted root updated to TreeSize %v", c.trusted.TreeSize)
	Vlog.Printf("✓ Log root updated.")
	return slr, smr, nil
}
