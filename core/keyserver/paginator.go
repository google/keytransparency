// Copyright 2018 Google Inc. All Rights Reserved.
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

package keyserver

import (
	"encoding/base64"

	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/google/keytransparency/core/mutator"
	"github.com/google/keytransparency/core/sequencer/metadata"

	rtpb "github.com/google/keytransparency/core/keyserver/readtoken_go_proto"
	spb "github.com/google/keytransparency/core/sequencer/sequencer_go_proto"
)

// EncodeToken converts a protobuf into a URL-safe base64 encoded string.
func EncodeToken(msg proto.Message) (string, error) {
	b, err := proto.Marshal(msg)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// DecodeToken turns a URL-safe base64 encoded protobuf back into its proto.
func DecodeToken(token string, msg proto.Message) error {
	b, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return err
	}
	return proto.Unmarshal(b, msg)
}

// SourceList is a paginator for a list of source slices.
type SourceList []*spb.MapMetadata_SourceSlice

// ParseToken will return the first token if token is "", otherwise it will try to parse the read token.
func (s SourceList) ParseToken(token string) (*rtpb.ReadToken, error) {
	if token == "" {
		return s.First(), nil
	}
	var rt rtpb.ReadToken
	if err := DecodeToken(token, &rt); err != nil {
		return nil, err
	}
	return &rt, nil
}

// First returns the first read parameters for this source.
func (s SourceList) First() *rtpb.ReadToken {
	if len(s) == 0 {
		// Empty struct means there is nothing else to page through.
		return &rtpb.ReadToken{}
	}
	wm := metadata.FromProto(s[0]).LowMark()
	return &rtpb.ReadToken{
		SliceIndex:     0,
		StartWatermark: wm.Value(),
	}
}

// Next returns the next read token. Returns an empty struct when the read is finished.
// lastRow is the (batchSize)th row from the last read, or nil if fewer than
// batchSize + 1 rows were returned.
func (s SourceList) Next(rt *rtpb.ReadToken, lastRow *mutator.LogMessage) *rtpb.ReadToken {
	if lastRow != nil {
		// There are more items in this source slice.
		return &rtpb.ReadToken{
			SliceIndex:     rt.SliceIndex,
			StartWatermark: lastRow.ID.Value(),
		}
	}

	// Advance to the next slice.
	if rt.SliceIndex >= int64(len(s))-1 {
		// There are no more source slices to iterate over.
		return &rtpb.ReadToken{} // Encodes to ""
	}

	wm := metadata.FromProto(s[rt.SliceIndex+1]).LowMark()
	return &rtpb.ReadToken{
		SliceIndex:     rt.SliceIndex + 1,
		StartWatermark: wm.Value(),
	}
}
