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

// This package contains common type definitions and functions used by other
// packages. Types that can cause circular import should be added here.
package common

import (
	"crypto/hmac"
	"crypto/sha256"
)

// GenerateProfileCommitment calculates and returns the profile commitment based
// on the provided nonce. Commitment is HMAC(profile, nonce).
func GenerateProfileCommitment(nonce []byte, profile []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, nonce)
	if _, err := mac.Write(profile); err != nil {
		return nil, err
	}
	return mac.Sum(nil), nil
}

// VerifyProfileCommitment returns true if the profile commitment using the
// nonce matches the provided commitment.
func VerifyProfileCommitment(nonce []byte, profile []byte, commitment []byte) (bool, error) {
	expectedCommitment, err := GenerateProfileCommitment(nonce, profile)
	if err != nil {
		return false, err
	}
	return hmac.Equal(expectedCommitment, commitment), nil
}
