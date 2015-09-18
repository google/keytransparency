// Copyright 2015 Google Inc. All Rights Reserved.
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

package keyserver

import (
	"testing"

	"github.com/google/e2e-key-server/client"

	v2pb "github.com/google/e2e-key-server/proto/v2"
)

func TestValidateEmail(t *testing.T) {
	env := NewEnv(t)
	defer env.Close(t)

	if err := env.server.validateEmail(env.ctx, primaryUserEmail); err != nil {
		t.Errorf("ValidateEmail failed: %v.", err)
	}

	if err := env.server.validateEmail(env.ctx, "invalid@gmail.com"); err == nil {
		t.Errorf("ValidateEmail did not fail for invalid user.")
	}
}

func TestValidateKey(t *testing.T) {
	env := NewEnv(t)
	defer env.Close(t)

	if err := env.server.validateKey(primaryUserEmail, primaryAppId, primaryKeys[primaryAppId]); err != nil {
		t.Errorf("validateKey() = %v, wanted nil", err)
	}
}

func TestValidateUpdateEntryRequest(t *testing.T) {
	env := NewEnv(t)
	defer env.Close(t)

	// Use a fake previous entry.
	previous := &v2pb.GetEntryResponse{
		Index: []byte("Foo"),
	}
	updateEntryRequest, err := client.CreateUpdate(primaryUserProfile, primaryUserEmail, previous)
	if err != nil {
		t.Fatalf("Failed creating update: %v", err)
	}

	if err := env.server.validateUpdateEntryRequest(env.ctx, updateEntryRequest); err != nil {
		t.Errorf("validateUpdateEntryRequest(ctx, %v) = %v", updateEntryRequest, err)
	}
}
