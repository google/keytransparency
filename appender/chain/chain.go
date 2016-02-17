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
)

// Chain implements a hash chain.
type Chain struct {
	// TODO: replace with database operations.
	items [][]byte
}

func New() *Chain {
	return &Chain{make([][]byte, 10)}
}

func (c *Chain) Append(ctx context.Context, data []byte) error {
	c.items = append(c.items, data)
	return nil
}

func (c *Chain) GetHLast(ctx context.Context) ([]byte, error) {
	h := sha512.New512_256()
	return h.Sum(c.items[len(c.items)-1]), nil

}
