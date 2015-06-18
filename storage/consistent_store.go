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

package storage

import (
	pb "github.com/google/e2e-key-server/proto/v2"
)

type ConsistentStore interface {
	// Returns a Code.ALREADY_EXISTS error if a promise for the same (user_id, key_id) already exists
	InsertPromise(promise *pb.KeyPromise) error

	// Lists the current promises for that user
	ListPromises(userId string) ([]*pb.KeyPromise, error)
}
