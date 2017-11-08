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

package fake

import (
	"context"
	"fmt"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/google/keytransparency/core/adminstorage"
	"github.com/google/trillian/crypto/keyspb"
)

// AdminStorage implements adminstorage.Storage
type AdminStorage struct {
	domains map[string]*adminstorage.Domain
}

// NewAdminStorage returns a fake adminstorage.Storage
func NewAdminStorage() *AdminStorage {
	return &AdminStorage{
		domains: make(map[string]*adminstorage.Domain),
	}
}

// List returns a list of active domains
func (a *AdminStorage) List(ctx context.Context, deleted bool) ([]*adminstorage.Domain, error) {
	ret := make([]*adminstorage.Domain, 0, len(a.domains))
	for _, d := range a.domains {
		ret = append(ret, d)
	}
	return ret, nil
}

// Write adds a new domain.
func (a *AdminStorage) Write(ctx context.Context,
	domainID string,
	mapID int64, logID int64,
	vrfPublicDER []byte, wrappedVRF proto.Message,
	minInterval, maxInterval time.Duration,
) error {
	a.domains[domainID] = &adminstorage.Domain{
		Domain:      domainID,
		MapID:       mapID,
		LogID:       logID,
		VRF:         &keyspb.PublicKey{Der: vrfPublicDER},
		VRFPriv:     wrappedVRF,
		MinInterval: minInterval,
		MaxInterval: maxInterval,
		Deleted:     false,
	}
	return nil
}

// Read returns existing domains.
func (a *AdminStorage) Read(ctx context.Context, ID string, showDeleted bool) (*adminstorage.Domain, error) {
	d, ok := a.domains[ID]
	if !ok {
		return nil, fmt.Errorf("Domain %v not found", ID)
	}
	return d, nil
}

// SetDelete deletes or undeletes a domain.
func (a *AdminStorage) SetDelete(ctx context.Context, ID string, isDeleted bool) error {
	_, ok := a.domains[ID]
	if !ok {
		return fmt.Errorf("Domain %v not found", ID)
	}
	a.domains[ID].Deleted = isDeleted
	return nil
}
