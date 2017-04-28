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

package fake

import (
	"github.com/google/trillian"
	"github.com/google/trillian/client"
)

type logVerifier struct{}

// NewFakeTrillianLogVerifier returns a verifier that passes all checks.
func NewFakeTrillianLogVerifier() client.LogVerifier {
	return &logVerifier{}
}

func (l *logVerifier) Root() trillian.SignedLogRoot {
	return trillian.SignedLogRoot{}
}

func (l *logVerifier) UpdateRoot(resp *trillian.GetLatestSignedLogRootResponse, consistency *trillian.GetConsistencyProofResponse) error {
	return nil
}

func (l *logVerifier) VerifyInclusionAtIndex(data []byte, leafIndex int64, resp *trillian.GetInclusionProofResponse) error {
	return nil
}

func (l *logVerifier) VerifyInclusionByHash(leafHash []byte, proof *trillian.Proof) error {
	return nil
}
