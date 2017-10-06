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
	"time"

	"github.com/golang/glog"

	"github.com/google/keytransparency/core/monitor/storage"
	ktpb "github.com/google/keytransparency/core/proto/keytransparency_v1_proto"

	"github.com/google/trillian"
	"github.com/google/trillian/client"
	tcrypto "github.com/google/trillian/crypto"
	"github.com/google/trillian/crypto/keys/der"
	"github.com/google/trillian/merkle/hashers"
)

// Monitor holds the internal state for a monitor accessing the mutations API
// and for verifying its responses.
type Monitor struct {
	mapID       int64
	mapHasher   hashers.MapHasher
	mapPubKey   crypto.PublicKey
	logVerifier client.LogVerifier
	signer      *tcrypto.Signer
	trusted     *trillian.SignedLogRoot
	store       *storage.Storage
}

// New creates a new instance of the monitor.
func New(logverifierCli client.LogVerifier, mapTree *trillian.Tree, signer *tcrypto.Signer, store *storage.Storage) (*Monitor, error) {
	mapHasher, err := hashers.NewMapHasher(mapTree.GetHashStrategy())
	if err != nil {
		return nil, fmt.Errorf("Failed creating MapHasher: %v", err)
	}
	mapPubKey, err := der.UnmarshalPublicKey(mapTree.GetPublicKey().GetDer())
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal map public key: %v", err)
	}
	return &Monitor{
		logVerifier: logverifierCli,
		mapID:       mapTree.TreeId,
		mapHasher:   mapHasher,
		mapPubKey:   mapPubKey,
		signer:      signer,
		store:       store,
	}, nil
}

// Process processes a mutation response received from the keytransparency
// server. Processing includes verifying, signing and storing the resulting
// monitoring response.
func (m *Monitor) Process(resp *ktpb.GetMutationsResponse) error {
	var smr *trillian.SignedMapRoot
	var err error
	seen := time.Now().Unix()
	errs := m.VerifyMutationsResponse(resp)
	if len(errs) == 0 {
		glog.Infof("Successfully verified mutations response for epoch: %v", resp.Epoch)
		smr, err = m.signMapRoot(resp)
		if err != nil {
			glog.Errorf("Failed to sign map root for epoch %v: %v", resp.Epoch, err)
			return fmt.Errorf("m.signMapRoot(_): %v", err)
		}
	}
	if err := m.store.Set(resp.Epoch, seen, smr, resp, errs); err != nil {
		glog.Errorf("m.store.Set(%v, %v, _, _, %v): %v", resp.Epoch, seen, errs, err)
		return err
	}
	return nil
}
