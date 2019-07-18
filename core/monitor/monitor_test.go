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

package monitor

import (
	"context"
	"testing"

	"github.com/google/trillian/types"
)

func TestRevisionPairs(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		in  []byte
		out []struct {
			a, b byte
		}
	}{
		{in: []byte{0, 1, 2}, out: []struct{ a, b byte }{{0, 1}, {1, 2}}},
	} {
		revisions := make(chan *types.MapRootV1, len(tc.in)+1)
		pairs := make(chan RevisionPair, len(tc.out)+1)
		for _, i := range tc.in {
			revisions <- &types.MapRootV1{RootHash: []byte{i}}
		}
		close(revisions)
		if err := RevisionPairs(ctx, revisions, pairs); err != nil {
			t.Fatalf("RevisionPairs(): %v", err)
		}
		for i, p := range tc.out {
			pair := <-pairs
			if got, want := pair.A.RootHash[0], p.a; got != want {
				t.Errorf("pairs[%v].A.Revision %v, want %v", i, got, want)
			}
			if got, want := pair.B.RootHash[0], p.b; got != want {
				t.Errorf("pairs[%v].B.Revision %v, want %v", i, got, want)
			}
		}
	}
}
