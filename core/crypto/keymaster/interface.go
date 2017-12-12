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

// Package keymaster supports the concept of keysets. A signature may be
// verified by any one of many public keys, while only one active key is used
// sign new messages.
package keymaster

import (
	"github.com/google/keytransparency/core/crypto/signatures"

	kmpb "github.com/google/keytransparency/core/api/type/type_proto"
)

// Signer represents an object that can generate signatures with a single key.
type Signer interface {
	signatures.Signer
	// Status returns the status of the signer.
	Status() kmpb.SigningKey_KeyStatus
	// Activate activates the signer.
	Activate()
	// Deactivate deactivates the signer.
	Deactivate()
	// Deprecate sets the signer status to DEPRECATED.
	Deprecate()
	// Marshal marshals a signer object into a keymaster SigningKey message.
	Marshal() (*kmpb.SigningKey, error)
	// Clone creates a new instance of the signer object
	Clone() Signer
}

// Verifier represents an object that can verify signatures with a single key.
type Verifier interface {
	signatures.Verifier
	// Status returns the status of the verifier.
	Status() kmpb.VerifyingKey_KeyStatus
	// Deprecate sets the verifier status to DEPRECATED.
	Deprecate()
	// Marshal marshals a verifier object into a keymaster VerifyingKey
	// message.
	Marshal() (*kmpb.VerifyingKey, error)
	// Clone creates a new instance of the verifier object
	Clone() Verifier
}
