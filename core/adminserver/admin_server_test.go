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

package adminserver

import (
	"context"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/google/keytransparency/core/fake"
	"github.com/google/trillian"
	"github.com/google/trillian/crypto/keys/der"
	"github.com/google/trillian/crypto/keyspb"
	"github.com/google/trillian/storage/testdb"
	"github.com/google/trillian/testonly/integration"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	_ "github.com/google/trillian/merkle/coniks"    // Register hasher
	_ "github.com/google/trillian/merkle/objhasher" // Register hasher
)

func vrfKeyGen(ctx context.Context, spec *keyspb.Specification) (proto.Message, error) {
	return der.NewProtoFromSpec(spec)
}

func TestCreateRead(t *testing.T) {
	testdb.SkipIfNoMySQL(t)
	ctx := context.Background()
	storage := fake.NewDomainStorage()

	// Map server
	mapEnv, err := integration.NewMapEnv(ctx)
	if err != nil {
		t.Fatalf("Failed to create trillian map server: %v", err)
	}

	// Log server
	numSequencers := 1
	unused := ""
	logEnv, err := integration.NewLogEnv(ctx, numSequencers, unused)
	if err != nil {
		t.Fatalf("Failed to create trillian log server: %v", err)
	}

	svr := New(logEnv.Log, mapEnv.Map, logEnv.Admin, mapEnv.Admin, storage, vrfKeyGen)

	for _, tc := range []struct {
		domainID                 string
		minInterval, maxInterval time.Duration
	}{
		{
			domainID:    "testdomain",
			minInterval: 1 * time.Second,
			maxInterval: 5 * time.Second,
		},
	} {
		_, err := svr.CreateDomain(ctx, &pb.CreateDomainRequest{
			DomainId:    tc.domainID,
			MinInterval: ptypes.DurationProto(tc.minInterval),
			MaxInterval: ptypes.DurationProto(tc.maxInterval),
		})
		if err != nil {
			t.Fatalf("CreateDomain(): %v", err)
		}
		domain, err := svr.GetDomain(ctx, &pb.GetDomainRequest{DomainId: tc.domainID})
		if err != nil {
			t.Fatalf("GetDomain(): %v", err)
		}
		if got, want := domain.Log.TreeType, trillian.TreeType_LOG; got != want {
			t.Errorf("Log.TreeType: %v, want %v", got, want)
		}
		if got, want := domain.Map.TreeType, trillian.TreeType_MAP; got != want {
			t.Errorf("Map.TreeType: %v, want %v", got, want)
		}
	}
}
