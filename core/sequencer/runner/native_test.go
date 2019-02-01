// Copyright 2018 Google Inc. All Rights Reserved.
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

package runner

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/google/keytransparency/core/sequencer/mapper"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	tpb "github.com/google/trillian"
)

func TestJoin(t *testing.T) {
	for _, tc := range []struct {
		desc   string
		leaves []*tpb.MapLeaf
		msgs   []*mapper.IndexedUpdate
		want   []*Joined
	}{
		{
			desc:   "onerow",
			leaves: []*tpb.MapLeaf{{Index: []byte("A")}},
			msgs:   []*mapper.IndexedUpdate{{Index: []byte("A"), Update: &pb.EntryUpdate{}}},
			want: []*Joined{{
				Index:  []byte("A"),
				Leaves: []*tpb.MapLeaf{{Index: []byte("A")}},
				Msgs:   []*pb.EntryUpdate{{}},
			}},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			got := Join(tc.leaves, tc.msgs)
			if !cmp.Equal(got, tc.want) {
				t.Errorf("Join(): %v, want %v\n diff: %v",
					got, tc.want, cmp.Diff(got, tc.want))
			}
		})
	}
}
