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
	"reflect"
	"strings"
	"testing"

	"github.com/google/e2e-key-server/builder"
	"github.com/google/e2e-key-server/client"
	"github.com/google/e2e-key-server/common"
	"github.com/google/e2e-key-server/storage"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	proto "github.com/golang/protobuf/proto"
	cm "github.com/google/e2e-key-server/common/common_merkle"
	corepb "github.com/google/e2e-key-server/proto/google_security_e2ekeys_core"
	v2pb "github.com/google/e2e-key-server/proto/google_security_e2ekeys_v2"
)

const (
	primaryUserID     = 12345678
	primaryUserEmail  = "e2eshare.test@gmail.com"
	primaryAppId      = "pgp"
	testEpochDuration = 1
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
	s         *grpc.Server
	server    *Server
	conn      *grpc.ClientConn
	Client    *client.Client
	ctx       context.Context
	builder   *builder.Builder
	fakeStore *Fake_LocalStorage
}

// NewEnv sets up common resources for tests.
func NewEnv(t *testing.T) *Env {
	lis, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	_, port, err := net.SplitHostPort(lis.Addr().String())
	if err != nil {
		t.Fatal("Failed to parse listener address: %v", err)
	}
	addr := "localhost:" + port
	s := grpc.NewServer()

	// TODO: replace with test credentials for an authenticated user.
	ctx := context.Background()

	consistentStore := storage.CreateMem(ctx)
	store := &Fake_LocalStorage{}
	b := builder.NewForServer(consistentStore, store)
	server := New(consistentStore, b)
	v2pb.RegisterE2EKeyServiceServer(s, server)
	go s.Serve(lis)

	cc, err := grpc.Dial(addr, grpc.WithInsecure())
	if err != nil {
		t.Fatalf("Dial(%q) = %v", addr, err)
	}

	client := client.New(v2pb.NewE2EKeyServiceClient(cc))

	return &Env{s, server, cc, client, ctx, b, store}
}

// Close releases resources allocated by NewEnv.
func (env *Env) Close() {
	env.conn.Close()
	env.s.Stop()
	env.builder.Close()
}

func (env *Env) createPrimaryUser(t *testing.T) {
	updateEntryRequest, err := env.Client.Update(primaryUserProfile, primaryUserEmail)
	if err != nil {
		t.Fatalf("Error creating update request: %v", err)
	}

	// Insert valid user. Calling update if the user does not exist will
	// insert the user's profile.
	_, err = env.Client.UpdateEntry(env.ctx, updateEntryRequest)
	if err != nil {
		t.Errorf("CreateEntry got unexpected error %v.", err)
		return
	}

	env.mockSigner(t)
}

// Mock signer: create new epoch and store the signed epoch head in the fake
// local storage.
func (env *Env) mockSigner(t *testing.T) {
	lastCommitmentTS := uint64(1)
	epochHead, err := env.builder.CreateEpoch(lastCommitmentTS, true)
	if err != nil {
		t.Fatalf("Cannot create epoch: %v", err)
	}
	epochHeadData, err := proto.Marshal(epochHead)
	if err != nil {
		t.Fatalf("Unexpected epoch head marshaling error: %v", err)
	}
	signedEpochHead := &v2pb.SignedEpochHead{
		EpochHead: epochHeadData,
		// TODO: fill signatures.
	}
	info := &corepb.EpochInfo{
		SignedEpochHead:         signedEpochHead,
		LastCommitmentTimestamp: lastCommitmentTS,
	}
	// Store in fake local storage.
	env.fakeStore.WriteEpochInfo(nil, 0, info)
}

func TestCreateKey(t *testing.T) {
	t.Parallel()

	env := NewEnv(t)
	defer env.Close()

	env.createPrimaryUser(t)
}

func TestProofOfAbsence(t *testing.T) {
	t.Parallel()

	env := NewEnv(t)
	defer env.Close()

	// Test proof of absence for an empty branch.
	getNonExistantUser(t, env)

	// Test proof of absence for a leaf that shares a prefix with the
	// requested index.
	env.createPrimaryUser(t)
	getNonExistantUser(t, env)
}

func getNonExistantUser(t *testing.T, env *Env) {
	ctx := context.Background() // Unauthenticated request.
	res, err := env.Client.GetEntry(ctx, &v2pb.GetEntryRequest{Epoch: math.MaxUint64, UserId: "nobody"})
	if err != nil {
		t.Fatalf("Query for nonexistant failed %v", err)
	}

	if len(res.Profile) != 0 {
		t.Errorf("Profile returned for nonexistant user")
	}

	// Verify that there's at least a single SEH returned.
	if got, want := len(res.GetSignedEpochHeads()), 1; got < want {
		t.Errorf("len(GetSignedEpochHeads()) = %v, want >= %v", got, want)
	}

	// TODO(cesarghali): verify SEH signatures.

	// Pick one of the provided signed epoch heads.
	// TODO(cesarghali): better pick based on key ID.
	seh := res.GetSignedEpochHeads()[0]
	epochHead, err := common.EpochHead(seh)
	if err != nil {
		t.Fatalf("Unexpected getting epoch head error: %v", err)
	}
	expectedRoot := epochHead.Root

	// Verify merkle tree neighbors.
	var entryData []byte
	var index []byte
	if res.Entry != nil {
		entryData, err = proto.Marshal(res.Entry)
		if err != nil {
			t.Fatalf("Unexpected entry marshalling error: %v.", err)
		}
		index = res.Entry.Index
	} else {
		entryData = nil
		index = res.Index
	}

	if err := env.Client.VerifyMerkleTreeProof(res.MerkleTreeNeighbors, expectedRoot, index, entryData); err != nil {
		t.Errorf("GetUser(%v) merkle tree neighbors verification failed: %v", primaryUserEmail, err)
	}

	// TODO(cesarghali): verify IndexProof.
}

func TestGetValidUser(t *testing.T) {
	t.Parallel()

	env := NewEnv(t)
	defer env.Close()

	env.createPrimaryUser(t)

	ctx := context.Background() // Unauthenticated request.
	res, err := env.Client.GetEntry(ctx, &v2pb.GetEntryRequest{Epoch: math.MaxUint64, UserId: primaryUserEmail})

	if err != nil {
		t.Fatalf("GetEntry failed: %v", err)
	}

	// Unmarshaling the resulted profile.
	p := new(v2pb.Profile)
	if err := proto.Unmarshal(res.Profile, p); err != nil {
		t.Fatalf("Unexpected profile unmarshalling error: %v.", err)
	}

	// Verify profile commitment.
	if err := common.VerifyCommitment(primaryUserEmail, res.CommitmentKey, res.Profile, res.Entry.ProfileCommitment); err != nil {
		t.Errorf("GetEntry profile commitment verification failed: %v", err)
	}

	if got, want := len(p.GetKeys()), 1; got != want {
		t.Errorf("len(GetKeyList()) = %v, want; %v", got, want)
		return
	}
	if got, want := p.GetKeys(), primaryKeys; !reflect.DeepEqual(got, want) {
		t.Errorf("GetEntry(%v).GetKeys() = %v, want: %v", primaryUserEmail, got, want)
	}

	// Verify that there's at least a single SEH returned.
	if got, want := len(res.GetSignedEpochHeads()), 1; got < want {
		t.Errorf("len(GetSignedEpochHeads()) = %v, want >= %v", got, want)
	}

	// TODO(cesarghali): verify SEH signatures.

	// Pick one of the provided signed epoch heads.
	// TODO(cesarghali): better pick based on key ID.
	seh := res.GetSignedEpochHeads()[0]
	epochHead, err := common.EpochHead(seh)
	if err != nil {
		t.Fatalf("Unexpected getting epoch head error: %v", err)
	}
	expectedRoot := epochHead.Root

	// Verify merkle tree neighbors.
	entryData, err := proto.Marshal(res.Entry)
	if err != nil {
		t.Fatalf("Unexpected entry marshalling error: %v.", err)
	}
	if err := env.Client.VerifyMerkleTreeProof(res.MerkleTreeNeighbors, expectedRoot, res.Index, entryData); err != nil {
		t.Errorf("GetUser(%v) merkle tree neighbors verification failed: %v", primaryUserEmail, err)
	}

	// TODO(cesarghali): verify IndexProoc.
}

func getErr(ret interface{}, err error) error {
	return err
}

func TestUnimplemented(t *testing.T) {
	t.Parallel()

	env := NewEnv(t)
	defer env.Close()

	tests := []struct {
		desc string
		err  error
	}{
		{"ListEntryHistory", getErr(env.Client.ListEntryHistory(env.ctx, &v2pb.ListEntryHistoryRequest{}))},
		{"ListSEH", getErr(env.Client.ListSEH(env.ctx, &v2pb.ListSEHRequest{}))},
		{"ListUpdate", getErr(env.Client.ListUpdate(env.ctx, &v2pb.ListUpdateRequest{}))},
		{"ListSteps", getErr(env.Client.ListSteps(env.ctx, &v2pb.ListStepsRequest{}))},
	}
	for i, test := range tests {
		if got, want := grpc.Code(test.err), codes.Unimplemented; got != want {
			t.Errorf("Test[%v]: %v(ctx, emptypb) = %v, want %v.", i, test.desc, got, want)
		}
	}
}

// Verify that users cannot alter keys for other users.
func TestUnauthenticated(t *testing.T) {
	t.Parallel()

	env := NewEnv(t)
	defer env.Close()

	tests := []struct {
		desc string
		err  error
	}{
		{"UpdateEntry", getErr(env.Client.UpdateEntry(env.ctx, &v2pb.UpdateEntryRequest{UserId: "someoneelse"}))},
	}
	for i, test := range tests {
		if got, want := grpc.Code(test.err), codes.PermissionDenied; got != want {
			t.Errorf("Test[%v]: %v(ctx, emptypb) = %v, want %v.", i, test.desc, got, want)
		}
	}
}

// Implementing mock static storage.
type Fake_LocalStorage struct {
	info *corepb.EpochInfo
}

func (s *Fake_LocalStorage) ReadUpdate(ctx context.Context, key uint64) (*corepb.EntryStorage, error) {
	return nil, nil
}

func (s *Fake_LocalStorage) ReadEpochInfo(ctx context.Context, epoch uint64) (*corepb.EpochInfo, error) {
	if s.info == nil {
		epochHead := &v2pb.EpochHead{
			Epoch: epoch,
			Root:  cm.EmptyLeafValue(""),
		}
		epochHeadData, err := proto.Marshal(epochHead)
		if err != nil {
			return nil, grpc.Errorf(codes.Internal, "Cannot marshal epoch head")
		}
		seh := &v2pb.SignedEpochHead{EpochHead: epochHeadData}
		return &corepb.EpochInfo{
			SignedEpochHead:         seh,
			LastCommitmentTimestamp: 1,
		}, nil
	}
	return s.info, nil
}

func (s *Fake_LocalStorage) WriteUpdate(ctx context.Context, entry *corepb.EntryStorage) error {
	return nil
}

func (s *Fake_LocalStorage) WriteEpochInfo(ctx context.Context, primaryKey uint64, epochInfo *corepb.EpochInfo) error {
	s.info = epochInfo
	return nil
}

func (s *Fake_LocalStorage) Close() {
}
