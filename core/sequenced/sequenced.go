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

package sequenced

import "github.com/google/keytransparency/core/transaction"

// Sequenced stores a list of items that have been sequenced.
type Sequenced interface {
	// Write writes an object at a given epoch.
	Write(txn transaction.Txn, mapID, epoch int64, obj interface{}) error

	// Read retrieves a specific object at a given epoch.
	Read(txn transaction.Txn, mapID, epoch int64, obj interface{}) error

	// Latest returns the latest object and its epoch.
	Latest(txn transaction.Txn, mapID int64, obj interface{}) (int64, error)
}
