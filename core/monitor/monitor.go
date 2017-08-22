// Copyright 2017 Google Inc. All Rights Reserved.
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

package monitor

import (
	"crypto"
	"fmt"

	"github.com/google/trillian"
	"github.com/google/trillian/merkle"
	"github.com/google/trillian/merkle/hashers"

	tcrypto "github.com/google/trillian/crypto"
)

// Monitor holds the internal state for a monitor accessing the mutations API
// and for verifying its responses.
type Monitor struct {
	hasher      hashers.MapHasher
	logPubKey   crypto.PublicKey
	mapPubKey   crypto.PublicKey
	logVerifier merkle.LogVerifier
	signer      *tcrypto.Signer
	// TODO(ismail): update last trusted signed log root
	//trusted     trillian.SignedLogRoot
}

// New creates a new instance of the monitor.
func New(logTree, mapTree *trillian.Tree, signer *tcrypto.Signer) (*Monitor, error) {
	logHasher, err := hashers.NewLogHasher(logTree.GetHashStrategy())
	if err != nil {
		return nil, fmt.Errorf("Failed creating LogHasher: %v", err)
	}
	mapHasher, err := hashers.NewMapHasher(mapTree.GetHashStrategy())
	if err != nil {
		return nil, fmt.Errorf("Failed creating MapHasher: %v", err)
	}
	return &Monitor{
		hasher:      mapHasher,
		logVerifier: merkle.NewLogVerifier(logHasher),
		logPubKey:   logTree.GetPublicKey(),
		mapPubKey:   mapTree.GetPublicKey(),
		signer:      signer,
	}, nil
}
