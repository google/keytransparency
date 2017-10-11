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

package kt

import (
	"context"
	"crypto"
	"testing"

	"github.com/google/keytransparency/core/crypto/vrf/p256"
	"github.com/google/keytransparency/core/fake"
	"github.com/google/keytransparency/core/internal"
	"github.com/google/keytransparency/core/proto/keytransparency_v1_proto"

	"github.com/google/trillian"
	"github.com/google/trillian/crypto/keys/pem"
	"github.com/google/trillian/merkle/hashers"

	"github.com/golang/protobuf/ptypes/any"

	tcrypto "github.com/google/trillian/crypto"
	_ "github.com/google/trillian/merkle/coniks" // Register coniks
)

var (
	VRFPub = []byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5AV2WCmStBt4N2Dx+7BrycJFbxhW
f5JqSoyp0uiL8LeNYyj5vgklK8pLcyDbRqch9Az8jXVAmcBAkvaSrLW8wQ==
-----END PUBLIC KEY-----`)
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
)

func mustMetadataAsAny(t *testing.T, meta *keytransparency_v1_proto.MapperMetadata) *any.Any {
	m, err := internal.MetadataAsAny(meta)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// signs signs smr with s.
func sign(s crypto.Signer, smr *trillian.SignedMapRoot) *trillian.SignedMapRoot {
	signer := &tcrypto.Signer{Hash: crypto.SHA256, Signer: s}
	sig, err := signer.SignObject(smr)
	if err != nil {
		panic(err)
	}
	smr.Signature = sig
	return smr
}

// Test vectors were obtained by observing the integration tests, in particular by adding logging
// output around the calls to GetEntry and VerifyGetEntryResponse in grpc_client.go, and the input
// to merkle.VerifyMapInclusionProof in VerifyGetEntryResponse.
func TestVerifyGetEntryResponse(t *testing.T) {
	ctx := context.Background()

	vrfPub, err := p256.NewVRFVerifierFromPEM(VRFPub)
	if err != nil {
		t.Fatal(err)
	}
	mapPub, err := pem.UnmarshalPublicKey(testPubKey1)
	if err != nil {
		t.Fatal(err)
	}
	mapHasher, err := hashers.NewMapHasher(trillian.HashStrategy_CONIKS_SHA512_256)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := pem.UnmarshalPrivateKey(testPrivKey1, "")
	if err != nil {
		t.Fatal(err)
	}

	v := New(vrfPub, mapHasher, mapPub, fake.NewFakeTrillianLogVerifier())

	for _, tc := range []struct {
		desc          string
		wantErr       bool
		userID, appID string
		trusted       *trillian.SignedLogRoot
		in            *keytransparency_v1_proto.GetEntryResponse
	}{
		{
			desc:   "empty",
			userID: "noalice",
			appID:  "app",
			in: &keytransparency_v1_proto.GetEntryResponse{
				VrfProof:  []byte{0x46, 0xae, 0x42, 0xd5, 0x0f, 0x0e, 0x24, 0xa8, 0x22, 0xa3, 0xf1, 0x55, 0xc6, 0xcd, 0xa0, 0x7b, 0xf6, 0xbb, 0x1d, 0x47, 0x13, 0x22, 0x00, 0xc1, 0x4c, 0xe3, 0x80, 0x2c, 0x01, 0x2d, 0xad, 0x37, 0xa4, 0x32, 0xcf, 0x4a, 0x5e, 0xc9, 0xd5, 0x9b, 0x20, 0x5c, 0x68, 0xdd, 0x8f, 0xf4, 0x21, 0x51, 0x7e, 0x24, 0x77, 0xb0, 0xca, 0x9b, 0x60, 0xd0, 0x03, 0x63, 0x9a, 0x48, 0xaa, 0x26, 0x84, 0xa0, 0x04, 0x0b, 0x13, 0x89, 0xd7, 0xc6, 0x63, 0x22, 0x39, 0x18, 0x73, 0x72, 0xfa, 0x32, 0xf6, 0xeb, 0x03, 0x08, 0x5d, 0x07, 0x4e, 0x02, 0x3a, 0xc6, 0x7f, 0x89, 0xe8, 0x44, 0x27, 0xcb, 0x73, 0xdc, 0xf2, 0x2f, 0xcc, 0xcd, 0x90, 0x6e, 0x97, 0xcb, 0x22, 0xff, 0x6e, 0xdb, 0x74, 0x22, 0xbf, 0x28, 0x27, 0x9b, 0x9e, 0x26, 0x1a, 0xe4, 0xc6, 0x16, 0x59, 0x4f, 0x7d, 0xcc, 0xb9, 0x8e, 0x7d, 0x41, 0xf7},
				Committed: nil,
				LeafProof: &trillian.MapLeafInclusion{
					Leaf:      &trillian.MapLeaf{},
					Inclusion: make([][]byte, 256),
				},
				Smr: sign(signer, &trillian.SignedMapRoot{
					TimestampNanos: 1506524755543208185,
					RootHash:       []byte{0x0e, 0xfc, 0x54, 0xad, 0xe0, 0xfc, 0xe8, 0x76, 0x55, 0x8c, 0x97, 0x38, 0xf5, 0xaa, 0x89, 0xe4, 0xd9, 0x9c, 0x0b, 0x8b, 0x6f, 0xe0, 0xb6, 0x2d, 0xbf, 0x63, 0x59, 0xcf, 0xc2, 0xad, 0xbb, 0xd7},
					MapId:          9175411803742040796,
					MapRevision:    1,
					Metadata:       mustMetadataAsAny(t, &keytransparency_v1_proto.MapperMetadata{}),
				}),
			},
			wantErr: false,
		},
		{
			desc:    "Tree size 2",
			userID:  "nocarol",
			appID:   "app",
			trusted: &trillian.SignedLogRoot{},
			in: &keytransparency_v1_proto.GetEntryResponse{
				VrfProof:  []byte{0x9f, 0x8f, 0xb1, 0x41, 0xbc, 0x10, 0xcb, 0xe2, 0x02, 0xe8, 0x3e, 0x8a, 0xe2, 0xd0, 0xe7, 0xe3, 0xc9, 0xa2, 0x83, 0x94, 0x85, 0xf7, 0xca, 0x8f, 0x33, 0xb6, 0x52, 0x56, 0xb0, 0x76, 0x8e, 0xf9, 0x6e, 0x0c, 0x8a, 0x1c, 0xe6, 0x7d, 0x8b, 0xb6, 0x73, 0xb3, 0xae, 0x51, 0x36, 0x52, 0xab, 0x2b, 0x9d, 0x5a, 0x96, 0xdd, 0xae, 0x2a, 0x74, 0x74, 0x02, 0x6b, 0xdd, 0x16, 0x86, 0x70, 0x94, 0x15, 0x04, 0x7b, 0xcd, 0x07, 0x03, 0xb9, 0x69, 0xe3, 0x72, 0x35, 0xdb, 0xfc, 0xb2, 0xa3, 0x4c, 0x22, 0x6b, 0xaa, 0xce, 0x92, 0x6b, 0xcf, 0x02, 0x11, 0x78, 0x7b, 0x1f, 0x5c, 0x2f, 0xff, 0xb9, 0x34, 0x32, 0xa1, 0xd9, 0xba, 0xec, 0xa5, 0x9d, 0x5e, 0xa6, 0xbb, 0xb6, 0x77, 0x92, 0x4c, 0x0c, 0x2d, 0x76, 0xdf, 0xbe, 0x9e, 0xa0, 0x93, 0xde, 0xf5, 0xa1, 0xc1, 0x4e, 0x9e, 0x19, 0x39, 0x16, 0xfe, 0x60},
				Committed: nil,
				LeafProof: &trillian.MapLeafInclusion{
					Leaf: &trillian.MapLeaf{},
					Inclusion: append(make([][]byte, 255), []byte{
						92, 215, 13, 113, 97, 138, 214, 158, 13, 29, 227, 67, 236, 34, 215, 4, 76, 188, 79, 247, 149, 223, 227, 147, 86, 214, 90, 126, 192, 212, 113, 64,
					}),
				},
				Smr: sign(signer, &trillian.SignedMapRoot{
					TimestampNanos: 1506596629587264426,
					RootHash:       []byte{0x2c, 0x27, 0x03, 0xe0, 0x34, 0xf4, 0x00, 0x2f, 0x94, 0x1d, 0xfc, 0xea, 0x7a, 0x4e, 0x16, 0x03, 0xee, 0x8b, 0x4e, 0xe3, 0x75, 0xbd, 0xf8, 0x72, 0x5e, 0xb8, 0xaf, 0x04, 0xbf, 0xa3, 0xd1, 0x56},
					MapId:          2595744899657020594,
					MapRevision:    2,
					Metadata:       mustMetadataAsAny(t, &keytransparency_v1_proto.MapperMetadata{HighestFullyCompletedSeq: 1}),
				}),
			},
		},
	} {
		err := v.VerifyGetEntryResponse(ctx, tc.userID, tc.appID, tc.trusted, tc.in)
		if got, want := err != nil, tc.wantErr; got != want {
			t.Errorf("VerifyGetEntryResponse(%v, %v, %v, %v): %t, wantErr %t (err=%v)",
				tc.userID, tc.appID, tc.trusted, tc.in, got, want, err)
		}
	}
}
