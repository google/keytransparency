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

	"github.com/google/keytransparency/core/domain"
)

// DomainStorage implements domain.Storage
type DomainStorage struct {
	domains map[string]*domain.Domain
}

// NewDomainStorage returns a fake dominstorage.Storage
func NewDomainStorage() *DomainStorage {
	return &DomainStorage{
		domains: make(map[string]*domain.Domain),
	}
}

// List returns a list of active domains
func (a *DomainStorage) List(ctx context.Context, deleted bool) ([]*domain.Domain, error) {
	ret := make([]*domain.Domain, 0, len(a.domains))
	for _, d := range a.domains {
		ret = append(ret, d)
	}
	return ret, nil
}

// Write adds a new domain.
func (a *DomainStorage) Write(ctx context.Context, d *domain.Domain) error {
	a.domains[d.Domain] = d
	return nil
}

// Read returns existing domains.
func (a *DomainStorage) Read(ctx context.Context, ID string, showDeleted bool) (*domain.Domain, error) {
	d, ok := a.domains[ID]
	if !ok {
		return nil, fmt.Errorf("Domain %v not found", ID)
	}
	return d, nil
}

// SetDelete deletes or undeletes a domain.
func (a *DomainStorage) SetDelete(ctx context.Context, ID string, isDeleted bool) error {
	_, ok := a.domains[ID]
	if !ok {
		return fmt.Errorf("Domain %v not found", ID)
	}
	a.domains[ID].Deleted = isDeleted
	return nil
}
