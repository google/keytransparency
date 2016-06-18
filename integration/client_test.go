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

	"github.com/gdbelvin/e2e-key-server/authentication"
	"github.com/gdbelvin/e2e-key-server/client"
	"golang.org/x/net/context"

	pb "github.com/gdbelvin/e2e-key-server/proto/security_e2ekeys"
)

var (
	requiredScopes = []string{"https://www.googleapis.com/auth/userinfo.email"}
	primaryKeys    = map[string][]byte{
		"foo": []byte("bar"),
	}
)

func TestEmptyGetAndUpdate(t *testing.T) {
	auth := authentication.New()
	env := NewEnv(t)
	defer env.Close(t)
	env.Client.RetryCount = 0

	tests := []struct {
		want   bool
		insert bool
		ctx    context.Context
		userID string
	}{
		{false, false, context.Background(), "noalice"},
		{false, true, auth.NewContext("bob", requiredScopes), "bob"},
		{false, false, context.Background(), "nocarol"},
		{true, false, context.Background(), "bob"},
		{true, true, auth.NewContext("bob", requiredScopes), "bob"},
	}
	for _, tc := range tests {
		profile, err := env.Client.GetEntry(context.Background(), tc.userID)
		if err != nil {
			t.Errorf("GetEntry(%v): %v, want nil", tc.userID, err)
		}
		if got := profile != nil; got != tc.want {
			t.Errorf("GetEntry(%v): %v, want %v", tc.userID, profile, tc.want)
		}
		if tc.want {
			if got, want := len(profile.GetKeys()), 1; got != want {
				t.Errorf("len(GetKeys()) = %v, want; %v", got, want)
				return
			}
			if got, want := profile.GetKeys(), primaryKeys; !reflect.DeepEqual(got, want) {
				t.Errorf("GetKeys() = %v, want: %v", got, want)
			}
		}
		if tc.insert {
			req, err := env.Client.Update(tc.ctx, tc.userID, &pb.Profile{primaryKeys})
			if got, want := err, client.ErrRetry; got != want {
				t.Fatalf("Update(%v): %v, want %v", tc.userID, got, want)
			}
			if err := env.Signer.Sequence(); err != nil {
				t.Fatalf("Failed to sequence: %v", err)
			}
			if err := env.Signer.CreateEpoch(); err != nil {
				t.Fatalf("Failed to CreateEpoch: %v", err)
			}
			if err := env.Client.Retry(tc.ctx, req); err != nil {
				t.Errorf("Retry(%v): %v, want nil", req, err)
			}
		}
	}
}

func TestUpdateValidation(t *testing.T) {
	env := NewEnv(t)
	defer env.Close(t)
	env.Client.RetryCount = 0

	auth := authentication.New()
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
		{false, auth.NewContext("carol", nil), "bob", profile},
		{false, auth.NewContext("carol", nil), "carol", profile},
		{true, auth.NewContext("dave", requiredScopes), "dave", profile},
		{true, auth.NewContext("eve", requiredScopes), "eve", profile},
	}
	for _, tc := range tests {
		req, err := env.Client.Update(tc.ctx, tc.userID, tc.profile)
		if got := err == client.ErrRetry; got != tc.want {
			t.Fatalf("Update(%v): %v, want nil", tc.userID, err)
		}
		if tc.want {
			if err := env.Signer.Sequence(); err != nil {
				t.Fatalf("Failed to sequence: %v", err)
			}
			if err := env.Signer.CreateEpoch(); err != nil {
				t.Fatalf("Failed to CreateEpoch: %v", err)
			}
			if err := env.Client.Retry(tc.ctx, req); err != nil {
				t.Errorf("Retry(%v): %v, want nil", req, err)
			}
		}
	}
}

// TODO: Test AppID filtering when implemented.
