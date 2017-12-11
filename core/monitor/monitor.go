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

	"github.com/google/keytransparency/core/client/mutationclient"
	"github.com/google/keytransparency/core/monitorstorage"

	"github.com/google/trillian"
	"github.com/google/trillian/client"
	"github.com/google/trillian/crypto/keys/der"
	"github.com/google/trillian/merkle/hashers"

	"github.com/golang/glog"

	pb "github.com/google/keytransparency/core/proto/keytransparency_v1_proto"
	tcrypto "github.com/google/trillian/crypto"
)

// Monitor holds the internal state for a monitor accessing the mutations API
// and for verifying its responses.
type Monitor struct {
	mClient     pb.MutationServiceClient
	signer      *tcrypto.Signer
	trusted     *trillian.SignedLogRoot
	mapID       int64
	logVerifier client.LogVerifier
	store       monitorstorage.Interface
	mapHasher   hashers.MapHasher
	mapPubKey   crypto.PublicKey
}

// NewFromConfig produces a new monitor from a DomainInfo object.
func NewFromConfig(mclient pb.MutationServiceClient,
	config *pb.GetDomainInfoResponse,
	signer *tcrypto.Signer,
	store monitorstorage.Interface) (*Monitor, error) {
	logTree := config.GetLog()
	mapTree := config.GetMap()
	logHasher, err := hashers.NewLogHasher(logTree.GetHashStrategy())
	if err != nil {
		return nil, fmt.Errorf("could not initialize log hasher: %v", err)
	}
	logPubKey, err := der.UnmarshalPublicKey(logTree.GetPublicKey().GetDer())
	if err != nil {
		return nil, fmt.Errorf("failed parsing log public key: %v", err)
	}
	mapHasher, err := hashers.NewMapHasher(mapTree.GetHashStrategy())
	if err != nil {
		return nil, fmt.Errorf("failed creating map hasher: %v", err)
	}
	mapPubKey, err := der.UnmarshalPublicKey(mapTree.GetPublicKey().GetDer())
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal map public key: %v", err)
	}
	logVerifier := client.NewLogVerifier(logHasher, logPubKey)
	return New(mclient, logVerifier,
		mapTree.TreeId, mapHasher, mapPubKey,
		signer, store)
}

// New creates a new instance of the monitor.
func New(mclient pb.MutationServiceClient,
	logVerifier client.LogVerifier,
	mapID int64, mapHasher hashers.MapHasher, mapPubKey crypto.PublicKey,
	signer *tcrypto.Signer,
	store monitorstorage.Interface) (*Monitor, error) {
	return &Monitor{
		mClient:     mclient,
		logVerifier: logVerifier,
		mapID:       mapID,
		mapHasher:   mapHasher,
		mapPubKey:   mapPubKey,
		signer:      signer,
		store:       store,
	}, nil
}

// ProcessLoop continuously fetches mutations and processes them.
func (m *Monitor) ProcessLoop(domainID string, period time.Duration) {
	mutCli := mutationclient.New(m.mClient, period)
	responses, errs := mutCli.StartPolling(domainID, 1)
	for {
		select {
		case mutResp := <-responses:
			glog.Infof("Received mutations response: %v", mutResp.Epoch)
			if err := m.Process(mutResp); err != nil {
				glog.Infof("Error processing mutations response: %v", err)
			}
		case err := <-errs:
			// this is OK if there were no mutations in  between:
			// TODO(ismail): handle the case when the known maxDuration has
			// passed and no epoch was issued?
			glog.Infof("Could not retrieve mutations API response %v", err)
		}
	}

}

// Process processes a mutation response received from the keytransparency
// server. Processing includes verifying, signing and storing the resulting
// monitoring response.
func (m *Monitor) Process(resp *pb.GetMutationsResponse) error {
	var smr *trillian.SignedMapRoot
	var err error
	errs := m.VerifyMutationsResponse(resp)
	if len(errs) == 0 {
		glog.Infof("Successfully verified mutations response for epoch: %v", resp.Epoch)
		smr, err = m.signMapRoot(resp)
		if err != nil {
			glog.Errorf("Failed to sign map root for epoch %v: %v", resp.Epoch, err)
			return fmt.Errorf("m.signMapRoot(_): %v", err)
		}
	}
	if err := m.store.Set(resp.Epoch, &monitorstorage.Result{
		Smr:      smr,
		Seen:     time.Now(),
		Errors:   errs,
		Response: resp,
	}); err != nil {
		return fmt.Errorf("monitorstorage.Set(%v, _): %v", resp.Epoch, err)
	}
	return nil
}
