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

package client

import (
	"reflect"
	"testing"

	"github.com/google/trillian/types"
)

func TestMapRevisionFor(t *testing.T) {
	for _, tc := range []struct {
		treeSize     uint64
		wantRevision uint64
		wantErr      error
	}{
		{treeSize: 1, wantRevision: 0},
		{treeSize: 0, wantRevision: 0, wantErr: ErrLogEmpty},
		{treeSize: ^uint64(0), wantRevision: ^uint64(0) - 1},
	} {
		revision, err := mapRevisionFor(&types.LogRootV1{TreeSize: tc.treeSize})
		if got, want := revision, tc.wantRevision; got != want {
			t.Errorf("mapRevisionFor(%v).Revision: %v, want: %v", tc.treeSize, got, want)
		}
		if got, want := err, tc.wantErr; got != want {
			t.Errorf("mapRevisionFor(%v).err: %v, want: %v", tc.treeSize, got, want)
		}
	}
}

func TestCompressHistory(t *testing.T) {
	for _, tc := range []struct {
		desc    string
		roots   map[uint64][]byte
		want    map[uint64][]byte
		wantErr error
	}{
		{
			desc: "Single",
			roots: map[uint64][]byte{
				1: []byte("a"),
			},
			want: map[uint64][]byte{
				1: []byte("a"),
			},
		},
		{
			desc: "Compress",
			roots: map[uint64][]byte{
				0: []byte("a"),
				1: []byte("a"),
				2: []byte("a"),
			},
			want: map[uint64][]byte{
				0: []byte("a"),
			},
		},
		{
			desc: "Not Contiguous",
			roots: map[uint64][]byte{
				0: []byte("a"),
				2: []byte("a"),
			},
			wantErr: ErrNonContiguous,
		},
		{
			desc: "Complex",
			roots: map[uint64][]byte{
				1: []byte("a"),
				2: []byte("a"),
				3: []byte("b"),
				4: []byte("b"),
				5: []byte("c"),
			},
			want: map[uint64][]byte{
				1: []byte("a"),
				3: []byte("b"),
				5: []byte("c"),
			},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := CompressHistory(tc.roots)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("compressHistory(): %#v, want %#v", got, tc.want)
			}
			if err != tc.wantErr {
				t.Errorf("compressHistory(): %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TODO(gbelvin): Implement stronger ListHistory testing
