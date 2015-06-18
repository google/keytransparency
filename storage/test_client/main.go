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

package main

import (
	"math/rand"
	"time"

	pb "github.com/google/e2e-key-server/proto/v2"
	. "github.com/google/e2e-key-server/storage"
)

func main() {
	rand.Seed(time.Now().UTC().UnixNano())
	machines := []string{"http://127.0.0.1:2379"}
	store := OpenEtcdStore(&EtcdConfiguration{machines, false})
	defer store.Close()
	keyId := "\x00 " + string(rand.Int31n(100))
	println("inserting key", keyId)
	err := store.InsertPromise(&pb.KeyPromise{
		SignedKeyTimestamp: &pb.SignedKeyTimestamp{
			UserId: "dmz@yahoo.com",
			SignedKey: &pb.SignedKey{
				KeyId: keyId,
			},
		},
	})
	if err != nil {
		panic(err)
	}
	println("listing")
	promises, err := store.ListPromises("dmz@yahoo.com")
	if err != nil {
		panic(err)
	}
	for _, promise := range promises {
		println("Key: ", promise.SignedKeyTimestamp.SignedKey.KeyId)
	}
}
