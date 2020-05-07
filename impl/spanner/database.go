// Copyright 2020 Google Inc. All Rights Reserved.
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

// Package spanner provides functions for interacting with cloudspanner.
package spanner

import (
	"context"
	"errors"

	"cloud.google.com/go/spanner"
)

var ErrNotInitializedYet = errors.New("not initialized yet")

type Database struct {
	client *spanner.Client
}

// New returns a non-blocking database handle
func New(ctx context.Context, name string) (*Database, error) {
	client, err := spanner.NewClient(ctx, name)
	if err != nil {
		return nil, err
	}

	return &Database{client: client}, nil
}

func NewForTest(client *spanner.Client) *Database {
	d := &Database{client: client}
	return d
}

func (d *Database) Get() *spanner.Client {
	return d.client
}
