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

// Tests for key_server.go

package keyserver

import (
	"encoding/hex"
	"math"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/e2e-key-server/storage"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	proto "github.com/golang/protobuf/proto"
	keyspb "github.com/google/e2e-key-server/proto/v2"
	context "golang.org/x/net/context"
	proto3 "google/protobuf"
)

const (
	primaryUserID    = 12345678
	primaryUserEmail = "test@gmail.com"
)

var (
	// Generated test key in End to End app and exported it.
	// New: Public Key Packet(tag 6)(82 bytes)
	// 	Ver 4 - new
	// 	Public key creation time - Wed Dec 31 16:00:00 PST 1969
	// 	Pub alg - Reserved for ECDSA(pub 19)
	// 	Unknown public key(pub 19)
	// New: User ID Packet(tag 13)(16 bytes)
	// 	User ID - <test@gmail.com>
	// New: Signature Packet(tag 2)(141 bytes)
	// 	Ver 4 - new
	// 	Sig type - Generic certification of a User ID and Public Key packet(0x10).
	// 	Pub alg - Reserved for ECDSA(pub 19)
	// 	Hash alg - SHA256(hash 8)
	// 	Hashed Sub: signature creation time(sub 2)(critical)(4 bytes)
	// 		Time - Tue May  5 17:13:00 PDT 2015
	// 	Hashed Sub: preferred symmetric algorithms(sub 11)(critical)(1 bytes)
	// 		Sym alg - AES with 256-bit key(sym 9)
	// 	Hashed Sub: issuer key ID(sub 16)(critical)(8 bytes)
	// 		Key ID - 0x51BCF536CDE77EAD
	// 	Hashed Sub: preferred hash algorithms(sub 21)(critical)(4 bytes)
	// 		Hash alg - SHA256(hash 8)
	// 		Hash alg - SHA384(hash 9)
	// 		Hash alg - SHA512(hash 10)
	// 		Hash alg - SHA224(hash 11)
	// 	Hashed Sub: preferred compression algorithms(sub 22)(critical)(2 bytes)
	// 		Comp alg - ZIP <RFC1951>(comp 1)
	// 		Comp alg - ZLIB <RFC1950>(comp 2)
	// 	Hashed Sub: key flags(sub 27)(critical)(1 bytes)
	// 		Flag - This key may be used to certify other keys
	// 		Flag - This key may be used to sign data
	// 	Hashed Sub: features(sub 30)(critical)(1 bytes)
	// 		Flag - Modification detection (packets 18 and 19)
	// 	Hash left 2 bytes - 35 fa
	// 	Unknown signature(pub 19)
	// New: Public Subkey Packet(tag 14)(86 bytes)
	// 	Ver 4 - new
	// 	Public key creation time - Wed Dec 31 16:00:00 PST 1969
	// 	Pub alg - Reserved for Elliptic Curve(pub 18)
	// 	Unknown public key(pub 18)
	// New: Signature Packet(tag 2)(109 bytes)
	// 	Ver 4 - new
	// 	Sig type - Subkey Binding Signature(0x18).
	// 	Pub alg - Reserved for ECDSA(pub 19)
	// 	Hash alg - SHA256(hash 8)
	// 	Hashed Sub: signature creation time(sub 2)(critical)(4 bytes)
	// 		Time - Tue May  5 17:13:00 PDT 2015
	// 	Hashed Sub: issuer key ID(sub 16)(critical)(8 bytes)
	// 		Key ID - 0x51BCF536CDE77EAD
	// 	Hashed Sub: key flags(sub 27)(critical)(1 bytes)
	// 		Flag - This key may be used to encrypt communications
	// 		Flag - This key may be used to encrypt storage
	// 	Hash left 2 bytes - 50 7d
	// 	Unknown signature(pub 19)
	primaryUserKeyRing, _ = hex.DecodeString(strings.Replace(`
c6ff00000052040000000013082a8648ce3d0301070203041dd84a957d81
f2f59981d6f3d116e938b0fc3b75d279398aebc297de18d2e0a658e01ca8
1fb0d1c3b8ca1f97ee0cea4306ac7257d3747cb24dd598aeaeaf673dcdff
000000103c7465737440676d61696c2e636f6d3ec2ff0000008d04101308
003fff000000058255495c8cff000000028b09ff000000099051bcf536cd
e77eadff000000059508090a0bff00000003960102ff000000029b03ff00
0000029e01000035fa00fe323ff19e38f293ddf564285b49101a69611590
a2bc3429757a31ccdef1470e1300ff4d6f023121e6c4a1a8ea513bc126ce
d1e2db21920e4699ab7e2c6168ec02c70dceff0000005604000000001208
2a8648ce3d030107020304132661d744a14a4e58575c9a2a0e4c5ddb0019
9a4eca4d7aae1c0afde2234b34b53f6fbdec79b87fd9b347b7120670079f
49449d7b8c96ded37d8526eb0f1f5403010807c2ff0000006d0418130800
1fff000000058255495c8cff000000099051bcf536cde77eadff00000002
9b0c0000507d00ff7dbdc210b4fa7e66f19f55c3c6a97effafaf15cc4a28
46c2602847cddde824650100eea58f82502c9319ec526ceda88b3e814d9b
f0dfdb5bb58299068beb8f4eb501`, "\n", "", -1))
	primarySignedKey = &keyspb.SignedKey{
		Key: &keyspb.SignedKey_Key{
			AppId:  "pgp",
			Key:    primaryUserKeyRing,
			Format: keyspb.SignedKey_Key_PGP_KEYRING,
			CreationTime: &proto3.Timestamp{
				Seconds: time.Now().Unix(),
			},
		},
	}
)

type Env struct {
	s      *grpc.Server
	server *Server
	conn   *grpc.ClientConn
	Client keyspb.E2EKeyServiceClient
	ctx    context.Context
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
	server := Create(storage.CreateMem(context.Background()))
	keyspb.RegisterE2EKeyServiceServer(s, server)
	go s.Serve(lis)

	cc, err := grpc.Dial(addr, grpc.WithTimeout(time.Millisecond*500))
	if err != nil {
		t.Fatalf("Dial(%q) = %v", addr, err)
	}

	client := keyspb.NewE2EKeyServiceClient(cc)
	// TODO: replace with test credentials for an authenticated user.
	ctx := context.Background()

	return &Env{s, server, cc, client, ctx}
}

// Close releases resources allocated by NewEnv.
func (env *Env) Close() {
	env.conn.Close()
	env.s.Stop()
}

func (env *Env) createPrimaryUser(t *testing.T) {
	// insert valid user
	res, err := env.Client.CreateKey(env.ctx, &keyspb.CreateKeyRequest{
		UserId:    primaryUserEmail,
		SignedKey: primarySignedKey,
	})
	if err != nil {
		t.Errorf("CreateKey got unexpected error %v.", err)
		return
	}
	if res.GetSignedKeyTimestamp() == nil {
		t.Errorf("Missing signed key timestamp.")
	}
	if res.GetSignedKeyTimestamp().GetCreationTime() == nil {
		t.Errorf("Missing server timestamp.")
	}
	nowSecs := time.Now().Unix()
	timestamp := res.GetSignedKeyTimestamp()
	if got, want := math.Abs(float64(timestamp.GetCreationTime().Seconds)-float64(nowSecs)), 2.0; got > want {

		t.Errorf("GetCreationTime().Seconds = %v, want: %v", got, want)
	}
	if got, want := timestamp.GetSignedKey().GetKey(), primarySignedKey.GetKey(); !proto.Equal(got, want) {
		t.Errorf("GetSignedKey() = %v, want %v.", got, want)
	}
}

func TestGetNonExistantUser(t *testing.T) {
	env := NewEnv(t)
	defer env.Close()

	ctx := context.Background() // Unauthenticated request.
	_, err := env.Client.GetUser(ctx, &keyspb.GetUserRequest{UserId: "nobody"})

	if got, want := grpc.Code(err), codes.NotFound; got != want {
		t.Errorf("Query for nonexistant user = %v, want: %v", got, want)
	}
}

func TestGetValidUser(t *testing.T) {
	env := NewEnv(t)
	defer env.Close()

	env.createPrimaryUser(t)

	ctx := context.Background() // Unauthenticated request.
	res, err := env.Client.GetUser(ctx, &keyspb.GetUserRequest{UserId: primaryUserEmail})

	if err != nil {
		t.Errorf("GetUser failed: %v", err)
	}
	if got, want := len(res.GetUser().GetKeyList().GetSignedKeys()), 1; got != want {
		t.Errorf("len(GetSignedKeys()) = %v, want; %v", got, want)
		return
	}
	if got, want := res.GetUser().GetKeyList().GetSignedKeys()[0].GetKey(), primarySignedKey.Key; !proto.Equal(got, want) {
		t.Errorf("GetUser(%v) = %v, want: %v", primaryUserEmail, got, want)
	}
}

func TestCreateKey(t *testing.T) {
	env := NewEnv(t)
	defer env.Close()

	env.createPrimaryUser(t)
}

// You should not be able to create the same key twice.
func TestCreateDuplicateKey(t *testing.T) {
	env := NewEnv(t)
	defer env.Close()

	env.createPrimaryUser(t)
	_, err := env.Client.CreateKey(env.ctx, &keyspb.CreateKeyRequest{
		UserId:    primaryUserEmail,
		SignedKey: primarySignedKey,
	})
	if got, want := grpc.Code(err), codes.AlreadyExists; got != want {
		t.Errorf("CreateKey() = %v, want %v", got, want)
	}
}

func TestDeleteKey(t *testing.T) {
	env := NewEnv(t)
	defer env.Close()

	env.createPrimaryUser(t)
	if _, err := env.Client.DeleteKey(env.ctx, &keyspb.DeleteKeyRequest{
		UserId: primaryUserEmail,
	}); err != nil {
		t.Errorf("DeleteKey() failed: %v", err)
		return
	}
	_, err := env.Client.GetUser(env.ctx, &keyspb.GetUserRequest{UserId: primaryUserEmail})
	if got, want := grpc.Code(err), codes.NotFound; got != want {
		t.Errorf("Query for deleted user user = %v, want: %v", got, want)
	}
}

func getErr(ret interface{}, err error) error {
	return err
}

func TestUnimplemented(t *testing.T) {
	env := NewEnv(t)
	defer env.Close()

	tests := []struct {
		desc string
		err  error
	}{
		{"ListUserHistory", getErr(env.Client.ListUserHistory(env.ctx, &keyspb.ListUserHistoryRequest{}))},
	}
	for _, test := range tests {
		if got, want := grpc.Code(test.err), codes.Unimplemented; got != want {
			t.Errorf("%v(ctx, emptypb) = %v, want %v.", test.desc, got, want)
		}
	}
}

// Verify that users cannot alter keys for other users.
func TestUnauthenticated(t *testing.T) {
	env := NewEnv(t)
	defer env.Close()

	tests := []struct {
		desc string
		err  error
	}{
		{"CreateKey", getErr(env.Client.CreateKey(env.ctx, &keyspb.CreateKeyRequest{UserId: "someoneelse"}))},
		{"UpdateKey", getErr(env.Client.UpdateKey(env.ctx, &keyspb.UpdateKeyRequest{UserId: "someoneelse"}))},
		{"DeleteKey", getErr(env.Client.DeleteKey(env.ctx, &keyspb.DeleteKeyRequest{UserId: "someoneelse"}))},
	}
	for _, test := range tests {
		if got, want := grpc.Code(test.err), codes.PermissionDenied; got != want {
			t.Errorf("%v(ctx, emptypb) = %v, want %v.", test.desc, got, want)
		}
	}
}
