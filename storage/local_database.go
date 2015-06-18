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
	"time"

	pb "github.com/google/e2e-key-server/proto/v2"
)

type Update struct {
	Path     []byte
	NewValue *pb.User
}

type LocalDatabase interface {
	GetLatestSTR() (*pb.SignedRoot, error)
	GetSTRByNumber(number int64) (*pb.SignedRoot, error)

	// Read the newest version of an entry out of the local database, along with a proof.
	ReadNewest(index []byte) (*pb.UserProof, error)

	// Read the history of version of an entry, along with proofs for each version.
	// If startingAtEpoch is zero, this reads the entire history.
	ReadHistoric(index []byte, startingAtEpoch int64) ([]*pb.UserProof, error)

	// Create a new epoch, applying the given updates.
	AdvanceEpoch(time time.Time, updates []*Update) (*pb.Epoch, error)

	// Get the updates that made an epoch differ from its predecessor.
	GetEpochUpdates(epoch int64) ([]Update, error)
}
