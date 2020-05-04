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

// Package ktspanner provides functions for interacting with cloudspanner.
package ktspanner

import (
	"context"
	"errors"
	"fmt"

	"cloud.google.com/go/spanner"
)

var ErrNotInitializedYet = errors.New("not initialized yet")

type Database struct {
	name     string
	client   *spanner.Client
	initChan chan struct{}
}

// New returns a non-blocking database handle
func New(ctx context.Context, name string) (*Database, error) {
	d := &Database{name: name, initChan: make(chan struct{})}
	return d, d.initialize(ctx)
}

func NewForTest(client *spanner.Client) *Database {
	d := &Database{client: client, initChan: make(chan struct{})}
	close(d.initChan)
	return d
}

func (d *Database) initialize(ctx context.Context) error {
	client, err := spanner.NewClient(ctx, d.name)
	if err != nil {
		return err
	}
	d.client = client
	close(d.initChan)
	return nil
}

func (d *Database) Get(ctx context.Context) (*spanner.Client, error) {
	select {
	case <-d.initChan:
		return d.client, nil
	case <-ctx.Done():
		return nil, ErrNotInitializedYet
	}
}

// String describes the Database handle.
func (d *Database) String() string {
	return fmt.Sprintf("spanner.Database(name: %q)", d.name)
}
