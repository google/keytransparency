// Copyright 2016 Google Inc. All Rights Reserved.
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

package integration

import (
	"reflect"
	"testing"

	"github.com/google/key-transparency/authentication"
	"github.com/google/key-transparency/client"
	"golang.org/x/net/context"

	pb "github.com/google/key-transparency/proto/keytransparency_v1"
)

var (
	primaryKeys = map[string][]byte{
		"foo": []byte("bar"),
	}
)

func TestEmptyGetAndUpdate(t *testing.T) {
	auth := authentication.NewFake()
	env := NewEnv(t)
	defer env.Close(t)
	env.Client.RetryCount = 0

	tests := []struct {
		want   bool
		insert bool
		ctx    context.Context
		userID string
	}{
		{false, false, context.Background(), "noalice"}, // Empty
		{false, true, auth.NewContext("bob"), "bob"},    // Insert
		{false, false, context.Background(), "nocarol"}, // Empty
		{true, false, context.Background(), "bob"},      // Not Empty
		{true, true, auth.NewContext("bob"), "bob"},     // Update
	}
	for i, tc := range tests {
		profile, err := env.Client.GetEntry(context.Background(), tc.userID)
		if err != nil {
			t.Errorf("%v: GetEntry(%v): %v, want nil", i, tc.userID, err)
		}
		if got := profile != nil; got != tc.want {
			t.Errorf("%v: GetEntry(%v): %v, want %v", i, tc.userID, profile, tc.want)
		}
		if tc.want {
			if got, want := len(profile.GetKeys()), 1; got != want {
				t.Errorf("%v: len(GetKeys()) = %v, want; %v", i, got, want)
				return
			}
			if got, want := profile.GetKeys(), primaryKeys; !reflect.DeepEqual(got, want) {
				t.Errorf("%v: GetKeys() = %v, want: %v", i, got, want)
			}
		}
		if tc.insert {
			req, err := env.Client.Update(tc.ctx, tc.userID, &pb.Profile{primaryKeys})
			if got, want := err, client.ErrRetry; got != want {
				t.Fatalf("%v: Update(%v): %v, want %v", i, tc.userID, got, want)
			}
			if err := env.Signer.Sequence(); err != nil {
				t.Fatalf("%v: Failed to sequence: %v", i, err)
			}
			if err := env.Signer.CreateEpoch(); err != nil {
				t.Fatalf("%v: Failed to CreateEpoch: %v", i, err)
			}
			if err := env.Client.Retry(tc.ctx, req); err != nil {
				t.Errorf("%v: Retry(%v): %v, want nil", i, req, err)
			}
		}
	}
}

func TestUpdateValidation(t *testing.T) {
	env := NewEnv(t)
	defer env.Close(t)
	env.Client.RetryCount = 0

	auth := authentication.NewFake()
	profile := &pb.Profile{
		Keys: map[string][]byte{
			"foo": []byte("bar"),
		},
	}

	tests := []struct {
		want    bool
		ctx     context.Context
		userID  string
		profile *pb.Profile
	}{
		{false, context.Background(), "alice", profile},
		{false, auth.NewContext("carol"), "bob", profile},
		{true, auth.NewContext("dave"), "dave", profile},
		{true, auth.NewContext("eve"), "eve", profile},
	}
	for i, tc := range tests {
		req, err := env.Client.Update(tc.ctx, tc.userID, tc.profile)

		// The first update response is always a retry.
		if got, want := err, client.ErrRetry; (got == want) != tc.want {
			t.Fatalf("%v: Update(%v): %v != %v, want %v", i, tc.userID, err, want, tc.want)
		}
		if tc.want {
			if err := env.Signer.Sequence(); err != nil {
				t.Fatalf("%v: Failed to sequence: %v", i, err)
			}
			if err := env.Signer.CreateEpoch(); err != nil {
				t.Fatalf("%v: Failed to CreateEpoch: %v", i, err)
			}
			if err := env.Client.Retry(tc.ctx, req); err != nil {
				t.Errorf("%v: Retry(%v): %v, want nil", i, req, err)
			}
		}
	}
}

// TODO: Test AppID filtering when implemented.
