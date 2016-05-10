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

package authentication

import (
	"testing"

	"golang.org/x/net/context"
)

func TestValidateCreds(t *testing.T) {
	auth := New()
	tests := []struct {
		ctx            context.Context
		requiredUserID string
		requiredScopes []string
		want           bool
	}{
		{context.Background(), "foo", nil, false},
		{auth.NewContext("foo", nil), "foo", nil, true},
		{auth.NewContext("foo", nil), "foo", []string{"scope"}, false},
		{auth.NewContext("foo", []string{"scope"}), "foo", []string{"scope"}, true},
		{auth.NewContext("foo", []string{"other"}), "foo", []string{"scope"}, false},
		{auth.NewContext("foo", []string{"other", "scope"}), "foo", []string{"scope"}, true},
	}
	for _, tc := range tests {
		if got := auth.ValidateCreds(tc.ctx, tc.requiredUserID, tc.requiredScopes); got != tc.want {
			t.Errorf("ValidateCreds(%v, %v, %v): %v, want %v", tc.ctx, tc.requiredUserID, tc.requiredScopes, got, tc.want)
		}
	}
}
