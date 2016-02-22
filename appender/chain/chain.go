// Copyright 2015 Google Inc. All Rights Reserved.
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

package chain

import (
	"crypto/sha512"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

// Chain implements a hash chain.
type Chain struct {
	// TODO: replace with database operations.
	items [][]byte
	times map[int64]int
}

func New() *Chain {
	return &Chain{make([][]byte, 0), make(map[int64]int)}
}

func (c *Chain) Append(ctx context.Context, timestamp int64, data []byte) error {
	c.items = append(c.items, data)
	c.times[timestamp] = len(c.items) - 1
	return nil
}

func (c *Chain) Latest(ctx context.Context) int64 {
	return int64(len(c.items) - 1)
}

func (c *Chain) GetHLast(ctx context.Context) ([]byte, error) {
	h := sha512.New512_256()
	if len(c.items) == 0 {
		return []byte(""), nil
	}
	return h.Sum(c.items[len(c.items)-1]), nil
}

func (c *Chain) GetByIndex(ctx context.Context, index int64) ([]byte, error) {
	if index < 0 || index >= int64(len(c.items)) {
		return nil, grpc.Errorf(codes.NotFound, "Index not found: %v", index)
	}
	return c.items[index], nil
}

func (c *Chain) GetByTimeStamp(ctx context.Context, timestamp int64) ([]byte, error) {
	t, ok := c.times[timestamp]
	if !ok {
		return nil, grpc.Errorf(codes.NotFound, "Timestamp not found: %v", timestamp)
	}
	return c.items[t], nil
}
