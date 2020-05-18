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

package entry

import (
	"testing"

	"github.com/golang/protobuf/proto" //nolint:staticcheck

	"github.com/google/go-cmp/cmp"
	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	tpb "github.com/google/trillian"
)

const (
	// openssl ecparam -name prime256v1 -genkey -out p256-key.pem
	testPrivKey1 = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBoLpoKGPbrFbEzF/ZktBSuGP+Llmx2wVKSkbdAdQ+3JoAoGCCqGSM49
AwEHoUQDQgAE+xVOdphkfpEtl7OF8oCyvWw31dV4hnGbXDPbdFlL1nmayhnqyEfR
dXNlpBT2U9hXcSxliKI1rHrAJFDx3ncttA==
-----END EC PRIVATE KEY-----`
	// openssl ec -in p256-key.pem -pubout -out p256-pubkey.pem
	testPubKey1 = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+xVOdphkfpEtl7OF8oCyvWw31dV4
hnGbXDPbdFlL1nmayhnqyEfRdXNlpBT2U9hXcSxliKI1rHrAJFDx3ncttA==
-----END PUBLIC KEY-----`
	// openssl ecparam -name prime256v1 -genkey -out p256-key.pem
	testPrivKey2 = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGugtYzUjyysX/JtjAFA6K3SzgBSmNjog/3e//VWRLQQoAoGCCqGSM49
AwEHoUQDQgAEJKDbR4uyhSMXW80x02NtYRUFlMQbLOA+tLe/MbwZ69SRdG6Rx92f
9tbC6dz7UVsyI7vIjS+961sELA6FeR91lA==
-----END EC PRIVATE KEY-----`
	// openssl ec -in p256-key.pem -pubout -out p256-pubkey.pem
	testPubKey2 = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJKDbR4uyhSMXW80x02NtYRUFlMQb
LOA+tLe/MbwZ69SRdG6Rx92f9tbC6dz7UVsyI7vIjS+961sELA6FeR91lA==
-----END PUBLIC KEY-----`
)

func TestFromLeafValue(t *testing.T) {
	entry := &pb.SignedEntry{
		Entry: mustMarshal(t, &pb.Entry{Commitment: []byte{1, 2}}),
	}
	entryB := mustMarshal(t, entry)
	for _, tc := range []struct {
		desc    string
		leafVal []byte
		want    *pb.SignedEntry
		wantErr bool
	}{
		{desc: "empty leaf", leafVal: []byte{}, want: &pb.SignedEntry{}},
		{desc: "nil leaf", leafVal: nil, want: nil},
		{desc: "invalid", leafVal: []byte{2, 2, 2, 2, 2, 2, 2}, want: nil, wantErr: true},
		{desc: "valid", leafVal: entryB, want: entry},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := FromLeafValue(tc.leafVal)
			if (err != nil) != tc.wantErr {
				t.Fatalf("FromLeafValue(%v): %v, wantErr %v", tc.leafVal, err, tc.wantErr)
			}
			if !proto.Equal(got, tc.want) {
				t.Errorf("FromLeafValue(%v): \n%#v, want \n%#v", tc.leafVal, got, tc.want)
			}
		})
	}
}

func TestIndexedValue(t *testing.T) {
	iv := &IndexedValue{
		Index: []byte("index"),
		Value: &pb.EntryUpdate{
			Mutation:  &pb.SignedEntry{Entry: mustMarshal(t, &pb.Entry{Commitment: []byte{1, 2}})},
			Committed: &pb.Committed{},
		},
	}
	leaf, err := iv.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	for _, tc := range []struct {
		desc    string
		mapLeaf *tpb.MapLeaf
		want    *IndexedValue
		wantErr bool
	}{
		{desc: "empty leaf", mapLeaf: &tpb.MapLeaf{Index: []byte("index")}, want: &IndexedValue{Index: []byte("index")}},
		{desc: "invalid", mapLeaf: &tpb.MapLeaf{LeafValue: []byte{2, 2, 2, 2, 2, 2}}, want: &IndexedValue{}, wantErr: true},
		{desc: "valid", mapLeaf: leaf, want: iv},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			got := &IndexedValue{}
			if err := got.Unmarshal(tc.mapLeaf); (err != nil) != tc.wantErr {
				t.Fatalf("Unmarshal(%v): %v, wantErr %v", tc.mapLeaf, err, tc.wantErr)
			}
			if !cmp.Equal(got, tc.want, cmp.Comparer(proto.Equal)) {
				t.Errorf("Unmarshal(%v): \n%#v, want \n%#v, diff:\n%v",
					tc.mapLeaf, got, tc.want, cmp.Diff(got, tc.want))
			}
		})
	}
}
