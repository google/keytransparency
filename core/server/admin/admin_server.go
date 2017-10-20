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

// Package admin contains the KeyTransparencyAdminService implementation
package admin

import (
	"context"

	"github.com/google/keytransparency/core/crypto/vrf/p256"
	"github.com/google/keytransparency/core/storage/admin"
	"github.com/google/trillian"
	"github.com/google/trillian/crypto/keys"
	"github.com/google/trillian/crypto/keys/der"
	"github.com/google/trillian/crypto/keyspb"
	"github.com/google/trillian/crypto/sigpb"

	google_protobuf "github.com/golang/protobuf/ptypes/empty"
	gpb "github.com/google/keytransparency/core/proto/keytransparency_v1_grpc"
	pb "github.com/google/keytransparency/core/proto/keytransparency_v1_proto"
)

var (
	vrfKeySpec = &keyspb.Specification{
		Params: &keyspb.Specification_EcdsaParams{
			EcdsaParams: &keyspb.Specification_ECDSA{
				Curve: keyspb.Specification_ECDSA_P256,
			},
		},
	}
	logArgs = &trillian.CreateTreeRequest{
		Tree: &trillian.Tree{
			TreeState:          trillian.TreeState_ACTIVE,
			TreeType:           trillian.TreeType_LOG,
			HashStrategy:       trillian.HashStrategy_OBJECT_RFC6962_SHA256,
			SignatureAlgorithm: sigpb.DigitallySigned_ECDSA,
			HashAlgorithm:      sigpb.DigitallySigned_SHA256,
		},
		KeySpec: &keyspb.Specification{
			Params: &keyspb.Specification_EcdsaParams{
				EcdsaParams: &keyspb.Specification_ECDSA{
					Curve: keyspb.Specification_ECDSA_P256,
				},
			},
		},
	}
	mapArgs = &trillian.CreateTreeRequest{
		Tree: &trillian.Tree{
			TreeState:          trillian.TreeState_ACTIVE,
			TreeType:           trillian.TreeType_MAP,
			HashStrategy:       trillian.HashStrategy_CONIKS_SHA512_256,
			SignatureAlgorithm: sigpb.DigitallySigned_ECDSA,
			HashAlgorithm:      sigpb.DigitallySigned_SHA256,
		},
		KeySpec: &keyspb.Specification{
			Params: &keyspb.Specification_EcdsaParams{
				EcdsaParams: &keyspb.Specification_ECDSA{
					Curve: keyspb.Specification_ECDSA_P256,
				},
			},
		},
	}
)

type server struct {
	storage admin.Storage
	client  trillian.TrillianAdminClient
	keygen  keys.ProtoGenerator
}

// New returns a KeyTransparencyAdminService implementation.
func New(
	storage admin.Storage,
	client trillian.TrillianAdminClient,
	keygen keys.ProtoGenerator,
) gpb.KeyTransparencyAdminServiceServer {
	return &server{
		storage: storage,
		client:  client,
		keygen:  keygen,
	}
}

func (s *server) BatchUpdateEntries(ctx context.Context, in *pb.BatchUpdateEntriesRequest) (*pb.BatchUpdateEntriesResponse, error) {
	panic("not implemented")
}

// ListDomains produces a list of the configured domains
func (s *server) ListDomains(ctx context.Context, in *pb.ListDomainsRequest) (*pb.ListDomainsResponse, error) {
	domains, err := s.storage.List(ctx, in.GetShowDeleted())
	if err != nil {
		return nil, err
	}

	resp := make([]*pb.Domain, 0, len(domains))
	for _, d := range domains {
		info, err := s.fetchDomainInfo(ctx, d)
		if err != nil {
			return nil, err
		}
		resp = append(resp, info)

	}
	return &pb.ListDomainsResponse{
		Domains: resp,
	}, nil
}

// fetchDomainInfo converts an amdin.Domain object into a pb.Domain object by fetching the relevant info from Trillian.
func (s *server) fetchDomainInfo(ctx context.Context, d *admin.Domain) (*pb.Domain, error) {
	logTree, err := s.client.GetTree(ctx, &trillian.GetTreeRequest{TreeId: d.LogID})
	if err != nil {
		return nil, err
	}
	mapTree, err := s.client.GetTree(ctx, &trillian.GetTreeRequest{TreeId: d.MapID})
	if err != nil {
		return nil, err
	}
	return &pb.Domain{
		DomainId: d.Domain,
		Log:      logTree,
		Map:      mapTree,
		Vrf:      d.VRF,
		Deleted:  d.Deleted,
	}, nil
}

// GetDomain retrieves the domain info for a given domain.
func (s *server) GetDomain(ctx context.Context, in *pb.GetDomainRequest) (*pb.GetDomainResponse, error) {
	domain, err := s.storage.Read(ctx, in.GetDomainId(), in.GetShowDeleted())
	if err != nil {
		return nil, err
	}
	info, err := s.fetchDomainInfo(ctx, domain)
	if err != nil {
		return nil, err
	}
	return &pb.GetDomainResponse{
		Domain: info,
	}, nil
}

// CreateDomain reachs out to Trillian to produce new trees.
func (s *server) CreateDomain(ctx context.Context, in *pb.CreateDomainRequest) (*pb.CreateDomainResponse, error) {
	// TODO(gbelvin): Test whether the domain exists before creating trees.

	// Generate VRF key.
	wrapped, err := s.keygen(ctx, vrfKeySpec)
	if err != nil {
		return nil, err
	}
	vrfPriv, err := p256.NewFromWrappedKey(ctx, wrapped)
	if err != nil {
		return nil, err
	}
	vrfPublicPB, err := der.ToPublicProto(vrfPriv.Public())
	if err != nil {
		return nil, err
	}

	// Create Trillian keys.
	logTree, err := s.client.CreateTree(ctx, logArgs)
	if err != nil {
		return nil, err
	}
	mapTree, err := s.client.CreateTree(ctx, mapArgs)
	if err != nil {
		return nil, err
	}

	if err := s.storage.Write(ctx, in.GetDomainId(), logTree.TreeId, mapTree.TreeId, vrfPublicPB.Der, wrapped); err != nil {
		return nil, err
	}
	return &pb.CreateDomainResponse{
		Domain: &pb.Domain{
			DomainId: in.GetDomainId(),
			Log:      logTree,
			Map:      mapTree,
			Vrf:      vrfPublicPB,
		},
	}, nil
}

func (s *server) DeleteDomain(ctx context.Context, in *pb.DeleteDomainRequest) (*google_protobuf.Empty, error) {
	if err := s.storage.SetDelete(ctx, in.GetDomainId(), true); err != nil {
		return nil, err
	}
	return &google_protobuf.Empty{}, nil
}

func (s *server) UndeleteDomain(ctx context.Context, in *pb.UndeleteDomainRequest) (*google_protobuf.Empty, error) {
	if err := s.storage.SetDelete(ctx, in.GetDomainId(), false); err != nil {
		return nil, err
	}
	return &google_protobuf.Empty{}, nil
}
