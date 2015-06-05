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

// Package storage provides an API to persistant storage, implemented with spanner.
package storage

import (
	"time"

	context "golang.org/x/net/context"
	keyspb "github.com/google/key-server-transparency/proto/v2"
)

type BasicStorage interface {
	// InsertLogTableRow ensures that there is a valid directory entry for our data.
	InsertLogTableRow(ctx context.Context)
	// UpdateKey updates a UserKey row. Fails if the row does not already exist.
	UpdateKey(ctx context.Context, signedKey *keyspb.SignedKey, vuf []byte) error
	// InsertKey inserts a new UserKey row. Fails if the row already exists.
	InsertKey(ctx context.Context, signedKey *keyspb.SignedKey, vuf []byte) error
	// DeleteKey deletes a key.
	DeleteKey(ctx context.Context, vuf []byte) error
	// ReadKey reads a key.
	ReadKey(ctx context.Context, vuf []byte) (*keyspb.SignedKey, error)
}

type ConiksStorage interface {
	// InsertLogTableRow ensures that there is a valid directory entry for our data.
	InsertLogTableRow(ctx context.Context)

	ReadProof(ctx context.Context, vuf []byte) (*keyspb.Proof, error)
	ReadHistoricProof(ctx context.Context, vuf []byte, epoch time.Time) (*keyspb.Proof, error)
	ReadKeys(ctx context.Context, vuf []byte) ([]*keyspb.SignedKey, error)
	ReadHistoricKeys(ctx context.Context, vuf []byte, epoch time.Time) ([]*keyspb.SignedKey, error)
	ReadKeyPromises(ctx context.Context, vuf []byte) ([]*keyspb.SignedKey, error)

	// InsertKey inserts a new UserKey row. Fails if the row already exists.
	InsertKeyPromise(ctx context.Context, signedKey *keyspb.SignedKey, vuf []byte) error
	// UpdateKey updates a UserKey row. Fails if the row does not already exist.
	UpdateKeyPromise(ctx context.Context, signedKey *keyspb.SignedKey, vuf []byte, keyid string) error
	// DeleteKey deletes a key.
	DeleteKeyPromise(ctx context.Context, vuf []byte, keyid string) error
}
