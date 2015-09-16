// Copyright 2015 Google Inc. All Rights Reserved.
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

package proxy

import (
	"bytes"
	"encoding/hex"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/e2e-key-server/builder"
	"github.com/google/e2e-key-server/client"
	"github.com/google/e2e-key-server/keyserver"
	"github.com/google/e2e-key-server/storage"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	corepb "github.com/google/e2e-key-server/proto/core"
	v1pb "github.com/google/e2e-key-server/proto/v1"
	v2pb "github.com/google/e2e-key-server/proto/v2"
)

const (
	primaryUserID     = 12345678
	primaryUserEmail  = "e2eshare.test@gmail.com"
	primaryAppId      = "pgp"
	primaryUserPGPKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mFIEAAAAABMIKoZIzj0DAQcCAwRNDJYwov/h0/XUVEALnyLf4PfMP3bGpJODLtkk
IXSAZaC7rKurE6F/h3r8Uq9TMiZO4lvYBLUYRyMQDfYidAaKtBk8ZTJlc2hhcmUu
dGVzdEBnbWFpbC5jb20+iI0EExMIAD//AAAABQJVjCNs/wAAAAIbA/8AAAACiwn/
AAAABZUICQoL/wAAAAOWAQL/AAAAAp4B/wAAAAmQSyDbFK+ygeMAAEaEAQDdUlAS
Pe+J7E7BZWMI+1lpfvHQsH1Tv6ubkkn9akJ91QD/eG3H3UIVH6KV/fXWft7pEva5
i6Jsx6ikO63kVWFbYaK4VgQAAAAAEggqhkjOPQMBBwIDBFpSLVgW2RSga/CUSF3a
2Wnv0kdeybCXdB/G1K+v2LaTb6bNtNu39DlDtf8XDm5u5kfLQcL5LFhDoDe5aGP0
2iUDAQgHiG0EGBMIAB//AAAABYJVjCNs/wAAAAKbDP8AAAAJkEsg2xSvsoHjAACz
NwEAtQEtl9jKzlGYeng4YskWACyDnba5o/rGwcoFjRf1BiwBAPFn0SrS6WSUpU0+
B+8k+PXDpFKMZHZYo/E6qtVrpdYT
=+kV0
-----END PGP PUBLIC KEY BLOCK-----`
)

var (
	primaryUserKeyRing, _ = hex.DecodeString(strings.Replace(`
9852040000000013082a8648ce3d0301070203044d0c9630a2ffe1d3f5d4
54400b9f22dfe0f7cc3f76c6a493832ed92421748065a0bbacabab13a17f
877afc52af5332264ee25bd804b5184723100df62274068ab4193c653265
73686172652e7465737440676d61696c2e636f6d3e888d04131308003fff
0000000502558c236cff000000021b03ff000000028b09ff000000059508
090a0bff00000003960102ff000000029e01ff00000009904b20db14afb2
81e3000046840100dd5250123def89ec4ec1656308fb59697ef1d0b07d53
bfab9b9249fd6a427dd500ff786dc7dd42151fa295fdf5d67edee912f6b9
8ba26cc7a8a43bade455615b61a2b856040000000012082a8648ce3d0301
070203045a522d5816d914a06bf094485ddad969efd2475ec9b097741fc6
d4afafd8b6936fa6cdb4dbb7f43943b5ff170e6e6ee647cb41c2f92c5843
a037b96863f4da2503010807886d04181308001fff0000000582558c236c
ff000000029b0cff00000009904b20db14afb281e30000b3370100b5012d
97d8cace51987a783862c916002c839db6b9a3fac6c1ca058d17f5062c01
00f167d12ad2e96494a54d3e07ef24f8f5c3a4528c647658a3f13aaad56b
a5d613`, "\n", "", -1))
	primaryKeys = map[string][]byte{
		primaryAppId: primaryUserKeyRing,
	}
	primaryUserProfile = &v2pb.Profile{
		// TODO(cesarghali): fill nonce.
		Keys: primaryKeys,
	}
)

type Env struct {
	v1srv     *Server
	v2srv     *keyserver.Server
	rpcServer *grpc.Server
	cc        *grpc.ClientConn
	ClientV1  v1pb.E2EKeyProxyClient
	// V2 client is needed in order to create user before using v1 client
	// to try to get it.
	ClientV2 *client.Client
	ctx      context.Context
}

// NewEnv sets up common resources for tests.
func NewEnv(t *testing.T) *Env {
	lis, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	_, port, err := net.SplitHostPort(lis.Addr().String())
	if err != nil {
		t.Fatal("Failed ot parse listener address: %v", err)
	}
	addr := "localhost:" + port
	s := grpc.NewServer()

	// TODO: replace with test credentials for an authenticated user.
	ctx := context.Background()

	consistentStore := storage.CreateMem(ctx)
	b := builder.New(consistentStore.NewEntries(), &Fake_StaticStorage{})
	v2srv := keyserver.New(consistentStore, b.GetTree(), b.GetEpoch())
	v1srv := New(v2srv)
	v2pb.RegisterE2EKeyServiceServer(s, v2srv)
	v1pb.RegisterE2EKeyProxyServer(s, v1srv)
	go s.Serve(lis)

	cc, err := grpc.Dial(addr, grpc.WithTimeout(time.Millisecond*500), grpc.WithInsecure())
	if err != nil {
		t.Fatalf("Dial(%q) = %v", addr, err)
	}

	clientv1 := v1pb.NewE2EKeyProxyClient(cc)
	clientv2 := client.New(v2pb.NewE2EKeyServiceClient(cc))

	return &Env{v1srv, v2srv, s, cc, clientv1, clientv2, ctx}
}

// Close releases resources allocated by NewEnv.
func (env *Env) Close() {
	env.cc.Close()
	env.rpcServer.Stop()
}

// createPrimaryUser creates a user using the v2 client. This function is copied
// from /keyserver/key_server_test.go.
func (env *Env) createPrimaryUser(t *testing.T) {
	updateEntryRequest, err := env.ClientV2.Update(primaryUserProfile, primaryUserEmail)
	if err != nil {
		t.Fatalf("Error creating update request: %v", err)
	}

	// Insert valid user. Calling update if the user does not exist will
	// insert the user's profile.
	_, err = env.ClientV2.UpdateEntry(env.ctx, updateEntryRequest)
	if err != nil {
		t.Errorf("UpdateEntry got unexpected error %v.", err)
		return
	}
}

func TestGetValidUser(t *testing.T) {
	env := NewEnv(t)
	defer env.Close()

	expectedPrimaryKeys := primaryKeys

	env.createPrimaryUser(t)

	ctx := context.Background() // Unauthenticated request.
	res, err := env.ClientV1.GetEntry(ctx, &v2pb.GetEntryRequest{UserId: primaryUserEmail})

	if err != nil {
		t.Errorf("GetEntry failed: %v", err)
	}
	if got, want := len(res.GetKeys()), 1; got != want {
		t.Errorf("len(GetKeyList()) = %v, want; %v", got, want)
		return
	}
	if got, want := res.GetKeys(), expectedPrimaryKeys; !reflect.DeepEqual(got, want) {
		t.Errorf("GetEntry(%v).GetKeys() = %v, want: %v", primaryUserEmail, got, want)
	}
}

func TestAppIDFiltering(t *testing.T) {
	env := NewEnv(t)
	defer env.Close()

	env.createPrimaryUser(t)

	ctx := context.Background() // Unauthenticated request.

	tests := []struct {
		appID        string
		outKeysCount int
		keyExists    bool
		key          []byte
		code         codes.Code
	}{
		{primaryAppId, 1, true, primaryUserKeyRing, codes.OK},
		{"gmail", 0, false, nil, codes.OK},
	}

	for i, test := range tests {
		res, err := env.ClientV1.GetEntry(ctx, &v2pb.GetEntryRequest{UserId: primaryUserEmail, AppId: test.appID})

		if got, want := grpc.Code(err), test.code; got != want {
			t.Errorf("Test[%v]: GetUser(%v)=%v, want %v", i, primaryUserEmail, got, want)
		}
		if got, want := len(res.GetKeys()), test.outKeysCount; got != want {
			t.Errorf("Test[%v]: len(GetKeyList()) = %v, want; %v", i, got, want)
			return
		}
		key, ok := res.GetKeys()[test.appID]
		if got, want := ok, test.keyExists; got != want {
			t.Errorf("Test[%v]: GetUser(%v) key of app ID '%v' does not exist", i, primaryUserEmail, test.appID)
		}
		if got, want := key, test.key; !reflect.DeepEqual(got, want) {
			t.Errorf("Test[%v]: GetUser(%v).GetKeys()[%v] = %v, want: %v", i, primaryUserEmail, test.appID, got, want)
		}
	}
}

func TestHkpLookup(t *testing.T) {
	env := NewEnv(t)
	defer env.Close()

	env.createPrimaryUser(t)
	ctx := context.Background() // Unauthenticated request.

	var tests = []struct {
		op             string
		userId         string
		options        string
		outBody        string
		outContentType string
		outNilErr      bool
	}{
		// This should return keys.
		{"get", primaryUserEmail, "", primaryUserPGPKey, "text/plain", true},
		{"get", primaryUserEmail, "mr", primaryUserPGPKey, "application/pgp-keys", true},
		// Looking up non-existing user.
		{"get", "nobody", "", "", "", false},
		// Unimplemented operations.
		{"index", primaryUserEmail, "", primaryUserPGPKey, "text/plain", false},
		{"vindex", primaryUserEmail, "", primaryUserPGPKey, "text/plain", false},
		{"index", "", "", "", "", false},
		{"vindex", "", "", "", "", false},
	}

	for i, test := range tests {
		hkpLookupReq := v1pb.HkpLookupRequest{
			Op:      test.op,
			Search:  test.userId,
			Options: test.options,
		}

		res, err := env.ClientV1.HkpLookup(ctx, &hkpLookupReq)
		if got, want := (err == nil), test.outNilErr; got != want {
			t.Errorf("Test[%v]: Unexpected err = (%v), want nil = %v", i, err, test.outNilErr)
		}
		if got, want := (res == nil), (err != nil); got != want {
			t.Errorf("Test[%v]: HkpLookup(%v) = (%v), want nil = %v", i, hkpLookupReq, res, want)
		}

		// If there's an output error, even expected, the test cannot be
		// completed.
		if err != nil {
			continue
		}

		buf := bytes.NewBuffer(res.Body)
		if gotb, wantb, gotct, wantct := buf.String(), test.outBody, res.ContentType, test.outContentType; gotb != wantb || gotct != wantct {
			t.Errorf("Test[%v]: HkpLookup(%v) = (%v, %v), want (%v, %v)", i, hkpLookupReq, gotct, gotb, wantct, wantb)
		}
	}
}

// Implementing mock static storage.
type Fake_StaticStorage struct {
}

func (s *Fake_StaticStorage) Read(ctx context.Context, key uint64) (*corepb.EntryStorage, error) {
	return nil, nil
}

func (s *Fake_StaticStorage) Write(ctx context.Context, entry *corepb.EntryStorage) error {
	return nil
}

func (s *Fake_StaticStorage) Close() {
}
