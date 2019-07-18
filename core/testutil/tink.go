// Copyright 2019 Google Inc. All Rights Reserved.
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

// Package testutil provides helper functions for tests.
package testutil

import (
	"fmt"

	"github.com/google/keytransparency/core/crypto/tinkio"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/testkeyset"
	"github.com/google/tink/go/tink"
)

// VerifyKeysetFromPEMs produces a Keyset with pubPEMs.
func VerifyKeysetFromPEMs(pubPEMs ...string) *keyset.Handle {
	handle, err := testkeyset.Read(&tinkio.ECDSAPEMKeyset{PEMs: pubPEMs})
	if err != nil {
		panic(fmt.Sprintf("insecure.KeysetHandle(): %v", err))
	}
	return handle
}

// SignKeysetsFromPEMs produces a slice of keysets, each with one private key.
func SignKeysetsFromPEMs(privPEMs ...string) []tink.Signer {
	signers := make([]tink.Signer, 0, len(privPEMs))
	for _, pem := range privPEMs {
		if pem == "" {
			continue
		}
		handle, err := testkeyset.Read(&tinkio.ECDSAPEMKeyset{PEMs: []string{pem}})
		if err != nil {
			panic(fmt.Sprintf("insecure.KeysetHandle(): %v", err))
		}
		signer, err := signature.NewSigner(handle)
		if err != nil {
			panic(fmt.Sprintf("testkeysethandle.NewSigner(): %v", err))
		}
		signers = append(signers, signer)
	}
	return signers
}
