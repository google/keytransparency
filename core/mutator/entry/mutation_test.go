// Copyright 2017 Google Inc. All Rights Reserved.
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

package entry

import (
	"testing"

	tpb "github.com/google/keytransparency/core/proto/keytransparency_v1_types"
)

func TestReplaceAuthorizedKeys(t *testing.T) {
	for _, tc := range []struct {
		pubKeys []*tpb.PublicKey
		wantErr bool
	}{
		{pubKeys: nil, wantErr: true},
		{pubKeys: []*tpb.PublicKey{{}}, wantErr: false},
	} {
		index := []byte("index")
		userID := "bob"
		appID := "app1"
		m, err := NewMutation(nil, index, userID, appID)
		if err != nil {
			t.Errorf("NewMutation(): %v", err)
		}

		err = m.ReplaceAuthorizedKeys(tc.pubKeys)
		if got, want := err != nil, tc.wantErr; got != want {
			t.Errorf("ReplaceAuthorizedKeys(%v): %v, wantErr: %v", tc.pubKeys, got, want)
		}
	}
}
