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
	"github.com/google/key-transparency/core/client/ctlog"

	ct "github.com/google/certificate-transparency/go"

	"github.com/google/key-transparency/core/proto/ctmap"
)

type fakeLog struct{}

// VerifySCT ensures that SMH has been properly included in the append only log.
func (fakeLog) VerifySCT(smh *ctmap.SignedMapHead, sct *ct.SignedCertificateTimestamp) error {
	return nil
}

// VerifySavedSCTs returns a list of SCTs that failed validation against the current STH.
func (fakeLog) VerifySavedSCTs() []ctlog.SCTEntry { return nil }

// UpdateSTH ensures that STH is at least 1 MMD from Now().
func (fakeLog) UpdateSTH() error { return nil }
