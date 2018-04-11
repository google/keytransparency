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

// Package storage defines storage interfaces.
package storage

import (
	"context"

	tpb "github.com/google/keytransparency/core/api/type/type_go_proto"
)

// KeySets gets and sets keysets.
type KeySets interface {
	// Get returns the keyset for a given domain and app.
	// instance supports hosting multiple usermanager servers on the same infrastructure.
	Get(ctx context.Context, instance int64, domainID, appID string) (*tpb.KeySet, error)
	// Set saves a keyset.
	Set(ctx context.Context, instance int64, domainID, appID string, k *tpb.KeySet) error
}
