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
	"crypto"
	"testing"

	"github.com/google/trillian"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_proto"
	tcrypto "github.com/google/trillian/crypto"
	_ "github.com/google/trillian/merkle/coniks"    // Register hasher
	_ "github.com/google/trillian/merkle/objhasher" // Register hasher
)

// Test vectors were obtained by observing the integration tests, in particular by adding logging
// output around the calls to GetEntry and VerifyGetEntryResponse in grpc_client.go, and the input
// to merkle.VerifyMapInclusionProof in VerifyGetEntryResponse.
func TestVerifyGetEntryResponse(t *testing.T) {
	ctx := context.Background()

	v, err := NewVerifierFromConfig(domainPB)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range getEntryResponses {
		t.Run(tc.desc, func(t *testing.T) {
			if err := v.VerifyGetEntryResponse(ctx, domainPB.DomainId, tc.appID, tc.userID, tc.trusted, tc.resp); err != nil {
				t.Errorf("VerifyGetEntryResponse(): %v)", err)
			}
		})
	}
}
