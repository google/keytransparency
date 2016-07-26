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

package client

import (
	ct "github.com/google/certificate-transparency/go"
	"github.com/google/key-transparency/proto/ctmap"
)

// FakeLog implmements no-op functions for testing.
type FakeLog int

// NewFakeLog creates a new fake log.
func NewFakeLog() *FakeLog {
	return new(FakeLog)
}

// VerifySCT ensures that SMH has been properly included in the append only log.
func (FakeLog) VerifySCT(smh *ctmap.SignedMapHead, sct *ct.SignedCertificateTimestamp) error {
	return nil
}

// VerifySCTs returns a list of SCTs that failed validation against the current STH.
func (FakeLog) VerifySCTs() []SCTEntry { return nil }

// UpdateSTH ensures that STH is at least 1 MMD from Now().
func (FakeLog) UpdateSTH() error { return nil }
