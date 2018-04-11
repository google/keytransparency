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

package keyserver

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/google/keytransparency/core/crypto/commitments"
	"github.com/google/keytransparency/core/crypto/vrf"
	"github.com/google/keytransparency/core/crypto/vrf/p256"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
)

var (
	primaryUserEmail = "e2eshare.test@gmail.com"
	primaryAppID     = "pgp"
	// Generated test key in End to End app and exported it.
	primaryUserKeyRing, _ = hex.DecodeString(strings.Replace(`
9852040000000013082a8648ce3d0301070203044d0c9630a2ffe1d3f5d4
54400b9f22dfe0f7cc3f76c6a493832ed92421748065a0bbacabab13a17f
877afc52af5332264ee25bd804b5184723100df62274068ab4193c653265
73686172652e7465737440676d61696c2e636f6d3e888d04131308003fff
0000000502558c236cff000000021b03ff000000028b09ff000000059508
090a0bff00000003960102ff000000029e01ff00000009904b20db14afb2
81e3000046840100dd5250123def89ec4ec1656308fb59697ef1d0b07d53
bfab9b9249fd6a427dd500ff786dc7dd42151fa295fdf5d67edee912f6b9
8ba26cc7a8a43bade455615b61a2b856040000000012082a8648ce3d0301
070203045a522d5816d914a06bf094485ddad969efd2475ec9b097741fc6
d4afafd8b6936fa6cdb4dbb7f43943b5ff170e6e6ee647cb41c2f92c5843
a037b96863f4da2503010807886d04181308001fff0000000582558c236c
ff000000029b0cff00000009904b20db14afb281e30000b3370100b5012d
97d8cace51987a783862c916002c839db6b9a3fac6c1ca058d17f5062c01
00f167d12ad2e96494a54d3e07ef24f8f5c3a4528c647658a3f13aaad56b
a5d613`, "\n", "", -1))
	primaryKeys = map[string][]byte{
		primaryAppID: primaryUserKeyRing,
	}
)

func TestValidateKey(t *testing.T) {
	for _, tc := range []struct {
		userID string
		appID  string
		key    []byte
		want   bool
	}{
		{primaryUserEmail, primaryAppID, primaryKeys[primaryAppID], true},
		{primaryUserEmail, "foo", []byte("junk"), true},
		{primaryUserEmail, primaryAppID, []byte("junk"), false},
	} {
		err := validateKey(tc.userID, tc.appID, tc.key)
		if got := err == nil; got != tc.want {
			t.Errorf("validateKey(%v, %v, %v) = %v, wanted %v", tc.userID, tc.appID, tc.key, err, tc.want)
		}
	}
}

func TestValidateUpdateEntryRequest(t *testing.T) {
	// Create and marshal a profile.
	profileData := []byte("bar")

	// Test verification for new entries.
	userID := "joe"
	appID := "app"
	vrfPriv, _ := p256.GenerateKey()
	index, _ := vrfPriv.Evaluate(vrf.UniqueID(userID, appID))
	nonce, err := commitments.GenCommitmentKey()
	if err != nil {
		t.Fatal(err)
	}
	commitment := commitments.Commit(userID, appID, profileData, nonce)

	for _, tc := range []struct {
		want       bool
		userID     string
		index      [32]byte
		commitment []byte
		nonce      []byte
	}{
		{false, userID, [32]byte{}, nil, nil},   // Incorrect index
		{false, userID, index, nil, nil},        // Incorrect commitment
		{false, userID, index, commitment, nil}, // Incorrect key
		{true, userID, index, commitment, nonce},
	} {
		req := &pb.UpdateEntryRequest{
			UserId: tc.userID,
			AppId:  appID,
			EntryUpdate: &pb.EntryUpdate{
				Mutation: &pb.Entry{
					Index:      tc.index[:],
					Commitment: tc.commitment,
				},
				Committed: &pb.Committed{
					Key:  tc.nonce,
					Data: profileData,
				},
			},
		}
		err := validateUpdateEntryRequest(req, vrfPriv)
		if got := err == nil; got != tc.want {
			t.Errorf("validateUpdateEntryRequest(%v): %v, want %v", req, err, tc.want)
		}
	}
}
