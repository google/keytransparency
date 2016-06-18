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

// package replace implements a simple replacement stragey as a mapper
package entry

import (
	"log"

	"github.com/golang/protobuf/proto"
	"github.com/gdbelvin/e2e-key-server/mutator"

	pb "github.com/gdbelvin/e2e-key-server/proto/security_e2ekeys"
)

// Replace defines mutations to simply replace the current map value with the
// contents of the mutation.
type Entry struct{}

func New() *Entry {
	return &Entry{}
}

// CheckMutation verifies that this is a valid mutation for this item.
func (*Entry) CheckMutation(oldValue, mutation []byte) error {
	update := new(pb.SignedKV)
	if err := proto.Unmarshal(mutation, update); err != nil {
		log.Printf("Error unmarshaling update: %v", err)
		return err
	}

	kv := new(pb.KeyValue)
	if err := proto.Unmarshal(update.KeyValue, kv); err != nil {
		log.Printf("Error unmarshaling keyvalue: %v", err)
		return err
	}
	entry := new(pb.Entry)
	if err := proto.Unmarshal(kv.Value, entry); err != nil {
		log.Printf("Error unmarshaling entry: %v", err)
		return err
	}
	// TODO: Verify pointer to previous data.
	// TODO: Verify signature from key in entry.

	if oldValue != nil {
		oldEntry := new(pb.Entry)
		if err := proto.Unmarshal(oldValue, oldEntry); err != nil {
			log.Printf("Error unmarshaling old entry: %v", err)
			return err
		}
		if got, want := entry.UpdateCount, oldEntry.UpdateCount; got <= want {
			log.Printf("UpdateCount: %v, want > %v", got, want)
			return mutator.ErrReplay
		}
		// TODO: Verify signature from key in oldEntry.
	}
	return nil
}

// Mutate applies mutation to value
func (*Entry) Mutate(value, mutation []byte) ([]byte, error) {
	update := new(pb.SignedKV)
	if err := proto.Unmarshal(mutation, update); err != nil {
		log.Printf("Error unmarshaling update: %v", err)
		return nil, err
	}
	kv := new(pb.KeyValue)
	if err := proto.Unmarshal(update.KeyValue, kv); err != nil {
		log.Printf("Error unmarshaling keyvalue: %v", err)
		return nil, err
	}

	return kv.Value, nil
}
