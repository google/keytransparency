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

package admin

import (
	"testing"

	"github.com/google/keytransparency/integration/fake"
)

func TestStatic(t *testing.T) {
	admin := NewStatic()
	client := fake.NewFakeTrillianClient()

	for _, tc := range []struct {
		logID     int64
		add, want bool
	}{
		{logID: 0, add: false, want: false},
		{logID: 1, add: true, want: true},
	} {
		if tc.add {
			if err := admin.AddLog(tc.logID, client); err != nil {
				t.Errorf("AddLog(): %v, want nil", err)
			}
		}
		_, err := admin.LogClient(tc.logID)
		if got, want := err == nil, tc.want; got != want {
			t.Errorf("LogClient(%v): %v, want nil? %v", tc.logID, err, want)
		}
	}
}
