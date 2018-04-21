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

// Package adminserver contains the KeyTransparencyAdmin implementation
package adminserver

import (
	"context"
	"fmt"
	"time"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"

	"github.com/google/keytransparency/core/crypto/vrf/p256"
	"github.com/google/keytransparency/core/domain"
	"github.com/google/trillian/client"
	"github.com/google/trillian/crypto/keys"
	"github.com/google/trillian/crypto/keys/der"
	"github.com/google/trillian/crypto/keyspb"
	"github.com/google/trillian/crypto/sigpb"

	google_protobuf "github.com/golang/protobuf/ptypes/empty"
	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	tpb "github.com/google/trillian"
)

var (
	logArgs = &tpb.CreateTreeRequest{
		Tree: &tpb.Tree{
			DisplayName:        "KT SMH Log",
			TreeState:          tpb.TreeState_ACTIVE,
			TreeType:           tpb.TreeType_LOG,
			HashStrategy:       tpb.HashStrategy_RFC6962_SHA256,
			SignatureAlgorithm: sigpb.DigitallySigned_ECDSA,
			HashAlgorithm:      sigpb.DigitallySigned_SHA256,
			MaxRootDuration:    ptypes.DurationProto(0 * time.Millisecond),
		},
	}
	mapArgs = &tpb.CreateTreeRequest{
		Tree: &tpb.Tree{
			DisplayName:        "KT Map",
			TreeState:          tpb.TreeState_ACTIVE,
			TreeType:           tpb.TreeType_MAP,
			HashStrategy:       tpb.HashStrategy_CONIKS_SHA512_256,
			SignatureAlgorithm: sigpb.DigitallySigned_ECDSA,
			HashAlgorithm:      sigpb.DigitallySigned_SHA256,
			MaxRootDuration:    ptypes.DurationProto(0 * time.Millisecond),
		},
	}
	keyspec = &keyspb.Specification{
		Params: &keyspb.Specification_EcdsaParams{
			EcdsaParams: &keyspb.Specification_ECDSA{
				Curve: keyspb.Specification_ECDSA_P256,
			},
		},
	}
)

// Server implements pb.KeyTransparencyAdminServer
type Server struct {
	tlog     tpb.TrillianLogClient
	tmap     tpb.TrillianMapClient
	logAdmin tpb.TrillianAdminClient
	mapAdmin tpb.TrillianAdminClient
	domains  domain.Storage
	keygen   keys.ProtoGenerator
}

// New returns a KeyTransparencyAdmin implementation.
func New(
	tlog tpb.TrillianLogClient,
	tmap tpb.TrillianMapClient,
	logAdmin, mapAdmin tpb.TrillianAdminClient,
	domains domain.Storage,
	keygen keys.ProtoGenerator,
) *Server {
	return &Server{
		tlog:     tlog,
		tmap:     tmap,
		logAdmin: logAdmin,
		mapAdmin: mapAdmin,
		domains:  domains,
		keygen:   keygen,
	}
}

// ListDomains produces a list of the configured domains
func (s *Server) ListDomains(ctx context.Context, in *pb.ListDomainsRequest) (*pb.ListDomainsResponse, error) {
	domains, err := s.domains.List(ctx, in.GetShowDeleted())
	if err != nil {
		return nil, err
	}

	resp := make([]*pb.Domain, 0, len(domains))
	for _, d := range domains {
		info, err := s.fetchDomain(ctx, d)
		if err != nil {
			return nil, err
		}
		resp = append(resp, info)

	}
	return &pb.ListDomainsResponse{
		Domains: resp,
	}, nil
}

// fetchDomain converts an adminstorage.Domain object into a pb.Domain object
// by fetching the relevant info from Trillian.
func (s *Server) fetchDomain(ctx context.Context, d *domain.Domain) (*pb.Domain, error) {
	logTree, err := s.logAdmin.GetTree(ctx, &tpb.GetTreeRequest{TreeId: d.LogID})
	if err != nil {
		return nil, err
	}
	mapTree, err := s.mapAdmin.GetTree(ctx, &tpb.GetTreeRequest{TreeId: d.MapID})
	if err != nil {
		return nil, err
	}
	return &pb.Domain{
		DomainId:    d.DomainID,
		Log:         logTree,
		Map:         mapTree,
		Vrf:         d.VRF,
		MinInterval: ptypes.DurationProto(d.MinInterval),
		MaxInterval: ptypes.DurationProto(d.MaxInterval),
		Deleted:     d.Deleted,
	}, nil
}

// GetDomain retrieves the domain info for a given domain.
func (s *Server) GetDomain(ctx context.Context, in *pb.GetDomainRequest) (*pb.Domain, error) {
	domain, err := s.domains.Read(ctx, in.GetDomainId(), in.GetShowDeleted())
	if err != nil {
		return nil, err
	}
	info, err := s.fetchDomain(ctx, domain)
	if err != nil {
		return nil, err
	}
	return info, nil
}

// privKeyOrGen returns the message inside privKey if privKey is not nil,
// otherwise, it generates a new key with keygen.
func privKeyOrGen(ctx context.Context, privKey *any.Any, keygen keys.ProtoGenerator) (proto.Message, error) {
	if privKey != nil {
		var keyProto ptypes.DynamicAny
		if err := ptypes.UnmarshalAny(privKey, &keyProto); err != nil {
			return nil, fmt.Errorf("failed to unmarshal privatekey: %v", err)
		}
		return keyProto.Message, nil
	}
	return keygen(ctx, keyspec)
}

// treeConfig returns a CreateTreeRequest
// - with a set PrivateKey is not nil, otherwise KeySpec is set.
// - with a tree description of "KT domain %v"
func treeConfig(treeTemplate *tpb.CreateTreeRequest, privKey *any.Any, domainID string) *tpb.CreateTreeRequest {
	config := *treeTemplate

	if privKey != nil {
		config.Tree.PrivateKey = privKey
	} else {
		config.KeySpec = keyspec
	}

	config.Tree.Description = fmt.Sprintf("KT domain %s", domainID)
	return &config
}

// CreateDomain reachs out to Trillian to produce new trees.
func (s *Server) CreateDomain(ctx context.Context, in *pb.CreateDomainRequest) (*pb.Domain, error) {
	// TODO(gbelvin): Test whether the domain exists before creating trees.

	// Generate VRF key.
	wrapped, err := privKeyOrGen(ctx, in.GetVrfPrivateKey(), s.keygen)
	if err != nil {
		return nil, fmt.Errorf("adminserver: keygen(): %v", err)
	}
	vrfPriv, err := p256.NewFromWrappedKey(ctx, wrapped)
	if err != nil {
		return nil, fmt.Errorf("adminserver: NewFromWrappedKey(): %v", err)
	}
	vrfPublicPB, err := der.ToPublicProto(vrfPriv.Public())
	if err != nil {
		return nil, err
	}

	// Create Trillian keys.
	logTreeArgs := treeConfig(logArgs, in.GetLogPrivateKey(), in.GetDomainId())
	logTree, err := client.CreateAndInitTree(ctx, logTreeArgs, s.logAdmin, s.tmap, s.tlog)
	if err != nil {
		return nil, fmt.Errorf("adminserver: CreateTree(log): %v", err)
	}
	mapTreeArgs := treeConfig(mapArgs, in.GetMapPrivateKey(), in.GetDomainId())
	mapTree, err := client.CreateAndInitTree(ctx, mapTreeArgs, s.mapAdmin, s.tmap, s.tlog)
	if err != nil {
		return nil, fmt.Errorf("adminserver: CreateAndInitTree(map): %v", err)
	}
	minInterval, err := ptypes.Duration(in.MinInterval)
	if err != nil {
		return nil, fmt.Errorf("adminserver: Duration(%v): %v", in.MinInterval, err)
	}
	maxInterval, err := ptypes.Duration(in.MaxInterval)
	if err != nil {
		return nil, fmt.Errorf("adminserver: Duration(%v): %v", in.MaxInterval, err)
	}

	// Initialize log with first map root.
	if err := s.initialize(ctx, logTree, mapTree); err != nil {
		return nil, fmt.Errorf("adminserver: initialize of log %v and map %v failed: %v",
			logTree.TreeId, mapTree.TreeId, err)
	}

	if err := s.domains.Write(ctx, &domain.Domain{
		DomainID:    in.GetDomainId(),
		MapID:       mapTree.TreeId,
		LogID:       logTree.TreeId,
		VRF:         vrfPublicPB,
		VRFPriv:     wrapped,
		MinInterval: minInterval,
		MaxInterval: maxInterval,
	}); err != nil {
		return nil, fmt.Errorf("adminserver: domains.Write(): %v", err)
	}
	glog.Infof("Created domain %v", in.GetDomainId())
	return &pb.Domain{
		DomainId:    in.GetDomainId(),
		Log:         logTree,
		Map:         mapTree,
		Vrf:         vrfPublicPB,
		MinInterval: in.MinInterval,
		MaxInterval: in.MaxInterval,
	}, nil
}

// initialize inserts the first (empty) SignedMapRoot into the log if it is empty.
// This keeps the log leaves in-sync with the map which starts off with an
// empty log root at map revision 0.
func (s *Server) initialize(ctx context.Context, logTree, mapTree *tpb.Tree) error {
	logID := logTree.GetTreeId()
	mapID := mapTree.GetTreeId()

	logClient, err := client.NewFromTree(s.tlog, logTree)
	if err != nil {
		return fmt.Errorf("adminserver: could not create log client: %v", err)
	}

	// Wait for the latest log root to become available.
	logRoot, err := logClient.UpdateRoot(ctx)
	if err != nil {
		return fmt.Errorf("adminserver: UpdateRoot(): %v", err)
	}

	// TODO(gbelvin): does this need to be in a retry loop?
	resp, err := s.tmap.GetSignedMapRoot(ctx, &tpb.GetSignedMapRootRequest{MapId: mapID})
	if err != nil {
		return fmt.Errorf("adminserver: GetSignedMapRoot(%v): %v", mapID, err)
	}
	mapVerifier, err := client.NewMapVerifierFromTree(mapTree)
	if err != nil {
		return fmt.Errorf("adminserver: NewMapVerifierFromTree(): %v", err)
	}
	mapRoot, err := mapVerifier.VerifySignedMapRoot(resp.GetMapRoot())
	if err != nil {
		return fmt.Errorf("adminserver: VerifySignedMapRoot(): %v", err)
	}

	// If the tree is empty and the map is empty,
	// add the empty map root to the log.
	if logRoot.TreeSize != 0 || mapRoot.Revision != 0 {
		return nil // Init not needed.
	}

	glog.Infof("Initializing Trillian Log %v with empty map root", logID)

	// Non-blocking add leaf
	if err := logClient.AddLeaf(ctx, resp.GetMapRoot().GetMapRoot()); err != nil {
		return fmt.Errorf("adminserver: log.AddLeaf(): %v", err)
	}
	return nil
}

// DeleteDomain marks a domain as deleted, but does not immediately delete it.
func (s *Server) DeleteDomain(ctx context.Context, in *pb.DeleteDomainRequest) (*google_protobuf.Empty, error) {
	if err := s.domains.SetDelete(ctx, in.GetDomainId(), true); err != nil {
		return nil, err
	}
	return &google_protobuf.Empty{}, nil
}

// UndeleteDomain reactivates a deleted domain - provided that UndeleteDomain is called sufficiently soon after DeleteDomain.
func (s *Server) UndeleteDomain(ctx context.Context, in *pb.UndeleteDomainRequest) (*google_protobuf.Empty, error) {
	if err := s.domains.SetDelete(ctx, in.GetDomainId(), false); err != nil {
		return nil, err
	}
	return &google_protobuf.Empty{}, nil
}
