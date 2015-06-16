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

	keyspb "github.com/google/e2e-key-server/proto/v2"
)

func TestValidateEmail(t *testing.T) {
	env := NewEnv(t)
	defer env.Close()

	if err := env.server.validateEmail(env.ctx, primaryUserEmail); err != nil {
		t.Errorf("ValidateEmail failed: %v.", err)
	}

	if err := env.server.validateEmail(env.ctx, "invalid@gmail.com"); err == nil {
		t.Errorf("ValidateEmail did not fail for invalid user.")
	}
}

func TestValidateSignedKey(t *testing.T) {
	env := NewEnv(t)
	defer env.Close()

	signedKey := *primarySignedKey
	if err := env.server.validateSignedKey(primaryUserEmail, &signedKey); err != nil {
		t.Errorf("validateSignedKey(%v) = %v, wanted nil", &signedKey, err)
	}
	if signedKey.KeyId == "" {
		t.Errorf("KeyId of signed key was not filled.")
	}
}

func TestValidateCreateKeyRequest(t *testing.T) {
	env := NewEnv(t)
	defer env.Close()

	createKeyRequest := &keyspb.CreateKeyRequest{
		UserId:    primaryUserEmail,
		SignedKey: primarySignedKey,
	}

	if err := env.server.validateCreateKeyRequest(env.ctx, createKeyRequest); err != nil {
		t.Errorf("validateCreateKeyRequest(ctx, %v) = %v", createKeyRequest, err)
	}
}

func TestValidateUpdateKeyRequest(t *testing.T) {
	env := NewEnv(t)
	defer env.Close()

	updateKeyRequest := &keyspb.UpdateKeyRequest{
		UserId:    primaryUserEmail,
		SignedKey: primarySignedKey,
	}

	if err := env.server.validateUpdateKeyRequest(env.ctx, updateKeyRequest); err != nil {
		t.Errorf("validateCreateKeyRequest(ctx, %v) = %v", updateKeyRequest, err)
	}
}
