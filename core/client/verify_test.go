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

package client

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/google/keytransparency/core/testdata"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_proto"
	_ "github.com/google/trillian/merkle/coniks"    // Register hasher
	_ "github.com/google/trillian/merkle/objhasher" // Register hasher
	"github.com/google/trillian/types"
)

// Test vectors in core/testdata are generated by running
// go generate ./core/testvectors
func TestVerifyGetEntryResponse(t *testing.T) {
	ctx := context.Background()

	domainFile := "../testdata/domain.json"
	b, err := ioutil.ReadFile(domainFile)
	if err != nil {
		t.Fatalf("ReadFile(%v): %v", domainFile, err)
	}
	var domainPB pb.Domain
	if err := json.Unmarshal(b, &domainPB); err != nil {
		t.Fatalf("Unmarshal(): %v", err)
	}
	v, err := NewVerifierFromDomain(&domainPB)
	if err != nil {
		t.Fatal(err)
	}

	respFile := "../testdata/getentryresponse.json"
	b, err = ioutil.ReadFile(respFile)
	if err != nil {
		t.Fatalf("ReadFile(%v): %v", respFile, err)
	}
	var getEntryResponses []testdata.GetEntryResponseVector
	if err := json.Unmarshal(b, &getEntryResponses); err != nil {
		t.Fatalf("Unmarshal(): %v", err)
	}

	for _, tc := range getEntryResponses {
		t.Run(tc.Desc, func(t *testing.T) {
			trusted := types.LogRootV1{}
			if _, _, err := v.VerifyGetEntryResponse(ctx, domainPB.DomainId, tc.AppID, tc.UserID, trusted, tc.Resp); err != nil {
				t.Errorf("VerifyGetEntryResponse(): %v)", err)
			}
		})
	}
}
