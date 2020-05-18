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

	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/google/go-cmp/cmp"
	"github.com/google/keytransparency/core/mutator/entry"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
)

func TestJoin(t *testing.T) {
	for _, tc := range []struct {
		desc       string
		leaves     []*entry.IndexedValue
		msgs       []*entry.IndexedValue
		want       []*Joined
		wantMetric map[string]int
	}{
		{
			desc:   "onerow",
			leaves: []*entry.IndexedValue{{Index: []byte("A"), Value: &pb.EntryUpdate{UserId: "bob"}}},
			msgs:   []*entry.IndexedValue{{Index: []byte("A"), Value: &pb.EntryUpdate{}}},
			want: []*Joined{{
				Index:   []byte("A"),
				Values1: []*pb.EntryUpdate{{UserId: "bob"}},
				Values2: []*pb.EntryUpdate{{}},
			}},
			wantMetric: map[string]int{
				"Join1": 1,
				"Join2": 1,
			},
		},
	} {
		metrics := make(map[string]int)
		t.Run(tc.desc, func(t *testing.T) {
			got := make([]*Joined, 0)
			for g := range Join(tc.leaves, tc.msgs, func(label string) { metrics[label]++ }) {
				got = append(got, g)
			}
			if !cmp.Equal(got, tc.want, cmp.Comparer(proto.Equal)) {
				t.Errorf("Join(): %v, want %v\n diff: %v",
					got, tc.want, cmp.Diff(got, tc.want))
			}
			if !cmp.Equal(metrics, tc.wantMetric) {
				t.Errorf("metrics: %v, want %v\n diff: %v",
					metrics, tc.wantMetric, cmp.Diff(metrics, tc.wantMetric))
			}
		})
	}
}
