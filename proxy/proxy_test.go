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
	"net"
	"strings"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/google/e2e-key-server/keyserver"
	"github.com/google/e2e-key-server/storage"
	"google.golang.org/grpc"

	v1pb "github.com/google/e2e-key-server/proto/v1"
	v2pb "github.com/google/e2e-key-server/proto/v2"
	context "golang.org/x/net/context"
)

const (
	primaryUserID    = 12345678
	primaryUserEmail = "e2eshare.test@gmail.com"
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
	primaryKey = &v2pb.Key{
		AppId: "pgp",
		Key:   primaryUserKeyRing,
	}
	primaryUserProfile = &v2pb.Profile{
		// TODO(cesarghali): fill nonce.
		KeyList: []*v2pb.Key{
			primaryKey,
		},
	}
)

type Env struct {
	v1svr     *Server
	v2svr     *keyserver.Server
	rpcServer *grpc.Server
	cc        *grpc.ClientConn
	ClientV1  v1pb.E2EKeyProxyClient
	// V2 client is needed in order to create user before using v1 client
	// to try to get it.
	ClientV2 v2pb.E2EKeyServiceClient
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
	v2svr := keyserver.Create(storage.CreateMem(context.Background()))
	v1svr := New(v2svr)
	v2pb.RegisterE2EKeyServiceServer(s, v2svr)
	v1pb.RegisterE2EKeyProxyServer(s, v1svr)
	go s.Serve(lis)

	cc, err := grpc.Dial(addr, grpc.WithTimeout(time.Millisecond*500))
	if err != nil {
		t.Fatalf("Dial(%q) = %v", addr, err)
	}

	clientv1 := v1pb.NewE2EKeyProxyClient(cc)
	clientv2 := v2pb.NewE2EKeyServiceClient(cc)
	// TODO: replace with test credentials for an authenticated user.
	ctx := context.Background()

	return &Env{v1svr, v2svr, s, cc, clientv1, clientv2, ctx}
}

// Close releases resources allocated by NewEnv.
func (env *Env) Close() {
	env.cc.Close()
	env.rpcServer.Stop()
}

// createPrimaryUser creates a user using the v2 client. This function is copied
// from /keyserver/key_server_test.go.
func (env *Env) createPrimaryUser(t *testing.T) {
	// Insert valid user. Calling update if the user does not exist will
	// insert the user's profile.
	p, err := proto.Marshal(primaryUserProfile)
	if err != nil {
		t.Fatalf("Unexpected profile marshalling error %v.", err)
	}
	_, err = env.ClientV2.UpdateUser(env.ctx, &v2pb.UpdateUserRequest{
		UserId: primaryUserEmail,
		Update: &v2pb.EntryUpdateRequest{
			Profile: p,
		},
	})
	if err != nil {
		t.Errorf("CreateUser got unexpected error %v.", err)
		return
	}
}

func TestGetValidUser(t *testing.T) {
	env := NewEnv(t)
	defer env.Close()

	expectedPrimaryKey := primaryKey

	env.createPrimaryUser(t)

	ctx := context.Background() // Unauthenticated request.
	res, err := env.ClientV1.GetUser(ctx, &v2pb.GetUserRequest{UserId: primaryUserEmail})

	if err != nil {
		t.Errorf("GetUser failed: %v", err)
	}
	if got, want := len(res.GetKeyList()), 1; got != want {
		t.Errorf("len(GetKeyList()) = %v, want; %v", got, want)
		return
	}
	if got, want := res.GetKeyList()[0], expectedPrimaryKey; !proto.Equal(got, want) {
		t.Errorf("GetUser(%v) = %v, want: %v", primaryUserEmail, got, want)
	}
}
