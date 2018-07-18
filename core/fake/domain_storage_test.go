// Copyright 2018 Google Inc. All Rights Reserved.
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
	"testing"

	"github.com/google/keytransparency/core/domain"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestDelete(t *testing.T) {
	s := NewDomainStorage()
	ctx := context.Background()
	for _, tc := range []struct {
		domainID string
	}{
		{domainID: "test"},
	} {
		d := &domain.Domain{DomainID: tc.domainID}
		if err := s.Write(ctx, d); err != nil {
			t.Errorf("Write(): %v", err)
		}
		if err := s.Delete(ctx, tc.domainID); err != nil {
			t.Errorf("Delete(): %v", err)
		}
		_, err := s.Read(ctx, tc.domainID, true)
		if got, want := status.Code(err), codes.NotFound; got != want {
			t.Errorf("Read(): %v, wanted %v", got, want)
		}
	}
}

func TestSetDelete(t *testing.T) {
	s := NewDomainStorage()
	ctx := context.Background()
	for _, tc := range []struct {
		domainID string
	}{
		{domainID: "test"},
	} {
		d := &domain.Domain{DomainID: tc.domainID}
		if err := s.Write(ctx, d); err != nil {
			t.Errorf("Write(): %v", err)
		}
		if err := s.SetDelete(ctx, tc.domainID, true); err != nil {
			t.Errorf("Delete(): %v", err)
		}
		_, err := s.Read(ctx, tc.domainID, false)
		if got, want := status.Code(err), codes.NotFound; got != want {
			t.Errorf("Read(): %v, wanted %v", got, want)
		}
	}
}

func TestList(t *testing.T) {
	s := NewDomainStorage()
	ctx := context.Background()
	domains := []*domain.Domain{
		{DomainID: "test1"},
		{DomainID: "test2", Deleted: true},
		{DomainID: "test3"},
	}
	for _, d := range domains {
		if err := s.Write(ctx, d); err != nil {
			t.Errorf("Write(): %v", err)
		}
		if d.Deleted {
			if err := s.SetDelete(ctx, d.DomainID, true); err != nil {
				t.Errorf("SetDelete(): %v", err)
			}
		}
	}
	ret, err := s.List(ctx, false)
	if err != nil {
		t.Errorf("List()): %v", err)
	}
	domainSet := make(map[string]bool)
	for _, d := range ret {
		domainSet[d.DomainID] = true
	}
	for _, d := range domains {
		if !d.Deleted && !domainSet[d.DomainID] {
			t.Errorf("Didn't find domain %v in output", d.DomainID)
		}
	}
}
