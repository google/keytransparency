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
	"encoding/hex"
	"math"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/google/e2e-key-server/keyserver"
	"github.com/google/e2e-key-server/storage"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	v1pb "github.com/google/e2e-key-server/proto/v1"
	v2pb "github.com/google/e2e-key-server/proto/v2"
	context "golang.org/x/net/context"
	proto3 "google/protobuf"
)

const (
	primaryUserID    = 12345678
	primaryUserEmail = "test@gmail.com"
)

var (
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

	primarySignedKey = &v2pb.SignedKey{
		Key: &v2pb.SignedKey_Key{
			AppId:     "pgp",
			KeyFormat: v2pb.SignedKey_Key_PGP_KEYRING,
			Key:       primaryUserKeyRing,
		},
	}
)

type Env struct {
	v1svr     *Server
	v2svr     *keyserver.Server
	rpcServer *grpc.Server
	conn      *grpc.ClientConn
	Client    v1pb.E2EKeyProxyClient
	ctx       context.Context
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
	v2svr := keyserver.Create(storage.CreateMem(context.Background()))
	v1svr := New(v2svr)
	v2pb.RegisterE2EKeyServiceServer(s, v2svr)
	v1pb.RegisterE2EKeyProxyServer(s, v1svr)
	go s.Serve(lis)

	cc, err := grpc.Dial(addr, grpc.WithTimeout(time.Millisecond*500))
	if err != nil {
		t.Fatalf("Dial(%q) = %v", addr, err)
	}

	client := v1pb.NewE2EKeyProxyClient(cc)
	// TODO: replace with test credentials for an authenticated user.
	ctx := context.Background()

	return &Env{v1svr, v2svr, s, cc, client, ctx}
}

// Close releases resources allocated by NewEnv.
func (env *Env) Close() {
	env.conn.Close()
	env.rpcServer.Stop()
}

func (env *Env) createPrimaryUser(t *testing.T) {
	// insert valid user
	res, err := env.Client.CreateKey(env.ctx, &v2pb.CreateKeyRequest{
		UserId:    primaryUserEmail,
		SignedKey: primarySignedKey,
	})
	if err != nil {
		t.Errorf("CreateKey got unexpected error %v.", err)
		return
	}
	// Verify that the server set the timestamp properly.
	nowSecs := time.Now().Unix()
	if got, want := math.Abs(float64(res.GetKey().GetCreationTime().Seconds)-float64(nowSecs)), 2.0; got > want {

		t.Errorf("GetCreationTime().Seconds = %v, want: %v", got, want)
	}
}

func TestGetValidUser(t *testing.T) {
	env := NewEnv(t)
	defer env.Close()

	expectedPrimarySignedKey := primarySignedKey
	expectedPrimarySignedKey.Key.CreationTime = &proto3.Timestamp{Seconds: time.Now().Unix()}
	env.createPrimaryUser(t)

	ctx := context.Background() // Unauthenticated request.
	res, err := env.Client.GetUser(ctx, &v2pb.GetUserRequest{UserId: primaryUserEmail})

	if err != nil {
		t.Errorf("GetUser failed: %v", err)
	}
	if got, want := len(res.GetSignedKeys()), 1; got != want {
		t.Errorf("len(GetSignedKeys()) = %v, want; %v", got, want)
		return
	}
	if got, want := res.GetSignedKeys()[0].GetKey(), expectedPrimarySignedKey.Key; !proto.Equal(got, want) {
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
	_, err := env.Client.CreateKey(env.ctx, &v2pb.CreateKeyRequest{
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
	if _, err := env.Client.DeleteKey(env.ctx, &v2pb.DeleteKeyRequest{
		UserId: primaryUserEmail,
	}); err != nil {
		t.Errorf("DeleteKey() failed: %v", err)
		return
	}
	_, err := env.Client.GetUser(env.ctx, &v2pb.GetUserRequest{UserId: primaryUserEmail})
	if got, want := grpc.Code(err), codes.NotFound; got != want {
		t.Errorf("Query for deleted user user = %v, want: %v", got, want)
	}
}
