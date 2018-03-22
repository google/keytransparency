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

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_proto"
	tpb "github.com/google/trillian"
)

func TestEpochPairs(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		in  []byte
		out []struct {
			a, b byte
		}
	}{
		{in: []byte{0, 1, 2}, out: []struct{ a, b byte }{{0, 1}, {1, 2}}},
	} {
		epochs := make(chan *pb.Epoch, len(tc.in)+1)
		pairs := make(chan EpochPair, len(tc.out)+1)
		for _, i := range tc.in {
			epochs <- &pb.Epoch{Smr: &tpb.SignedMapRoot{MapRoot: []byte{i}}}
		}
		close(epochs)
		if err := EpochPairs(ctx, epochs, pairs); err != nil {
			t.Fatalf("EpochPairs(): %v", err)
		}
		for i, p := range tc.out {
			pair := <-pairs
			if got, want := pair.A.Smr.MapRoot[0], p.a; got != want {
				t.Errorf("pairs[%v].A.Revision %v, want %v", i, got, want)
			}
			if got, want := pair.B.Smr.MapRoot[0], p.b; got != want {
				t.Errorf("pairs[%v].B.Revision %v, want %v", i, got, want)
			}
		}
	}
}
