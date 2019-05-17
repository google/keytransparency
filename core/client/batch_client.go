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
	"context"
	"runtime"
	"sync"

	"fmt"

	"github.com/google/tink/go/tink"
	"google.golang.org/grpc"

	"github.com/google/keytransparency/core/mutator/entry"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
)

// BatchCreateUser inserts mutations for new users that do not currently have entries.
// Calling BatchCreate for a user that already exists will produce no change.
func (c *Client) BatchCreateUser(ctx context.Context, users []*User,
	signers []tink.Signer, opts ...grpc.CallOption) error {
	// 1. Fetch user indexes
	userIDs := make([]string, 0, len(users))
	for _, u := range users {
		userIDs = append(userIDs, u.UserID)
	}
	indexByUser, err := c.BatchVerifyGetUserIndex(ctx, userIDs)
	if err != nil {
		return err
	}
	type result struct {
		m   *entry.Mutation
		err error
	}
	uChan := make(chan *User)
	rChan := make(chan result)
	go func() {
		defer close(uChan)
		for _, u := range users {
			uChan <- u
		}
	}()
	go func() {
		defer close(rChan)
		var wg sync.WaitGroup
		defer wg.Wait() // Wait before closing rChan
		for w := 0; w < runtime.NumCPU(); w++ {
			wg.Add(1)
			go func(uChan <-chan *User, rChan chan<- result) {
				defer wg.Done()
				for u := range uChan {
					mutation := entry.NewMutation(indexByUser[u.UserID], c.DirectoryID, u.UserID)
					if err := mutation.SetCommitment(u.PublicKeyData); err != nil {
						rChan <- result{err: err}
						continue
					}
					if u.AuthorizedKeys != nil {
						if err := mutation.ReplaceAuthorizedKeys(u.AuthorizedKeys); err != nil {
							rChan <- result{err: err}
							continue
						}
					}
					rChan <- result{m: mutation}
				}
			}(uChan, rChan)
		}
	}()
	mutations := make([]*entry.Mutation, 0, len(users))
	for r := range rChan {
		if r.err != nil {
			return r.err
		}
		mutations = append(mutations, r.m)
	}
	return c.BatchQueueUserUpdate(ctx, mutations, signers, opts...)
}

// BatchQueueUserUpdate signs the mutations and sends them to the server.
func (c *Client) BatchQueueUserUpdate(ctx context.Context, mutations []*entry.Mutation,
	signers []tink.Signer, opts ...grpc.CallOption) error {
	updates := make([]*pb.EntryUpdate, 0, len(mutations))
	for _, m := range mutations {
		update, err := m.SerializeAndSign(signers)
		if err != nil {
			return err
		}
		updates = append(updates, update)
	}

	req := &pb.BatchQueueUserUpdateRequest{DirectoryId: c.DirectoryID, Updates: updates}
	_, err := c.cli.BatchQueueUserUpdate(ctx, req, opts...)
	return err
}

// BatchCreateMutation fetches the current index and value for a list of users and prepares mutations.
func (c *Client) BatchCreateMutation(ctx context.Context, users []*User) ([]*entry.Mutation, error) {
	userIDs := make([]string, 0, len(users))
	for _, u := range users {
		userIDs = append(userIDs, u.UserID)
	}

	leavesByUserID, err := c.BatchVerifiedGetUser(ctx, userIDs)
	if err != nil {
		return nil, err
	}

	type result struct {
		m   *entry.Mutation
		err error
	}
	uChan := make(chan *User)
	rChan := make(chan result)

	// Allocate
	go func() {
		defer close(uChan)
		for _, u := range users {
			uChan <- u
		}
	}()
	// Workerpool
	go func() {
		defer close(rChan)
		var wg sync.WaitGroup
		defer wg.Wait() // Wait before closing rChan
		for w := 0; w < runtime.NumCPU(); w++ {
			wg.Add(1)
			go func(uChan <-chan *User, rChan chan<- result) {
				defer wg.Done()
				for u := range uChan {
					m, err := c.createMutation(u, leavesByUserID[u.UserID])
					rChan <- result{m: m, err: err}
				}
			}(uChan, rChan)
		}
	}()
	// Collect
	mutations := make([]*entry.Mutation, 0, len(users))
	for r := range rChan {
		if r.err != nil {
			return nil, r.err
		}
		mutations = append(mutations, r.m)
	}
	return mutations, nil
}

func (c *Client) createMutation(u *User, leaf *pb.MapLeaf) (*entry.Mutation, error) {
	if leaf == nil {
		return nil, fmt.Errorf("no leaf found for %v", u.UserID)
	}
	index, err := c.Index(leaf.GetVrfProof(), c.DirectoryID, u.UserID)
	if err != nil {
		return nil, err
	}
	mutation := entry.NewMutation(index, c.DirectoryID, u.UserID)

	leafValue := leaf.MapInclusion.GetLeaf().GetLeafValue()
	if err := mutation.SetPrevious(leafValue, true); err != nil {
		return nil, err
	}

	if err := mutation.SetCommitment(u.PublicKeyData); err != nil {
		return nil, err
	}

	if u.AuthorizedKeys != nil {
		if err := mutation.ReplaceAuthorizedKeys(u.AuthorizedKeys); err != nil {
			return nil, err
		}
	}
	return mutation, nil
}
