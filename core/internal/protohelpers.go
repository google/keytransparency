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

// Package internal gathers helpers used by code in ./core/... but not visible
// outside core.
package internal

import (
	"fmt"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"

	tpb "github.com/google/keytransparency/core/proto/keytransparency_v1_types"
	"github.com/google/trillian"
)

// MetadataFromMapRoot converts the google.protobuf.Any metadata field from the
// Trillian SignedMapRoot into a tpb.MapperMetadata, or returns an error if the
// field is absent or of the wrong type.
func MetadataFromMapRoot(r *trillian.SignedMapRoot) (*tpb.MapperMetadata, error) {
	if r.GetMetadata() == nil {
		return &tpb.MapperMetadata{}, nil
	}
	var metadataProto ptypes.DynamicAny
	if err := ptypes.UnmarshalAny(r.GetMetadata(), &metadataProto); err != nil {
		return nil, fmt.Errorf("Failed to unmarshal MapRoot.Metadata: %v", err)
	}
	return metadataProto.Message.(*tpb.MapperMetadata), nil
}

// MetadataAsAny marshals the supplied MapperMetadata proto into an 'any', which
// can be supplied as metadata to the Trillian map when setting leaves.
func MetadataAsAny(meta *tpb.MapperMetadata) (*any.Any, error) {
	if meta == nil {
		meta = &tpb.MapperMetadata{}
	}
	metaAny, err := ptypes.MarshalAny(meta)
	if err != nil {
		return nil, err
	}
	return metaAny, nil
}
