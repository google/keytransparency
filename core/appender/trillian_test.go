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

package appender

import (
	"context"
	"testing"

	"github.com/google/keytransparency/core/admin"
	"github.com/google/keytransparency/integration/fake"
)

func TestLatest(t *testing.T) {
	fakeLog := fake.NewFakeTrillianClient()
	admin := admin.NewStatic()
	if err := admin.AddLog(0, fakeLog); err != nil {
		t.Fatalf("failed to add log to admin: %v", err)
	}
	a := NewTrillian(admin)

	for _, tc := range []struct {
		logID int64
		epoch int64
		data  []byte
		want  int64
	}{
		{0, 0, []byte("foo"), 0},
		{0, 1, []byte("foo"), 1},
		{0, 2, []byte("foo"), 2},
	} {
		if err := a.Write(context.Background(), tc.logID, tc.epoch, tc.data); err != nil {
			t.Errorf("Append(%v, %v): %v, want nil", tc.epoch, tc.data, err)
		}

		var obj []byte
		epoch, err := a.Latest(context.Background(), tc.logID, &obj)
		if err != nil {
			t.Errorf("Latest(): %v, want nil", err)
		}
		if got := epoch; got != tc.want {
			t.Errorf("Latest(): %v, want %v", got, tc.want)
		}
	}
}
