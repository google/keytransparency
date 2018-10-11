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
	"sort"

	"github.com/golang/protobuf/proto"
	"github.com/google/keytransparency/core/mutator"

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

// SourceMap is a paginator for a map of sources.
type SourceMap map[int64]*spb.MapMetadata_SourceSlice

// First returns the first read parameters for this source.
func (s SourceMap) First() *rtpb.ReadToken {
	shardID := sortedKeys(s)[0]
	return &rtpb.ReadToken{
		ShardId:      shardID,
		LowWatermark: s[shardID].LowestWatermark,
	}
}

// Next returns the next read token. Returns an empty struct when the read is finished.
// lastRow is the (batchSize)th row from the last read, or nil if fewer than
// batchSize + 1 rows were returned.
func (s SourceMap) Next(rt *rtpb.ReadToken, lastRow *mutator.QueueMessage) *rtpb.ReadToken {
	if lastRow != nil {
		// There are more items in this shard.
		return &rtpb.ReadToken{
			ShardId:      rt.ShardId,
			LowWatermark: lastRow.ID,
		}
	}

	// Advance to the next shard.
	nextShard, ok := s.NextShard(rt.ShardId)
	if !ok {
		return &rtpb.ReadToken{} // Encodes to ""
	}
	return &rtpb.ReadToken{
		ShardId:      nextShard,
		LowWatermark: s[nextShard].LowestWatermark,
	}
}

// NextShard returns the next shardID from the SourceMap.
// Returns false if there are no more shards or shardID is not in SourceMap.
func (s SourceMap) NextShard(shardID int64) (int64, bool) {
	// Sorted list of shardIDs.
	shardIDs := sortedKeys(s)

	// Index of current shard.
	i := sort.Search(len(shardIDs), func(i int) bool { return shardIDs[i] >= shardID })
	if i == -1 {
		// shardID isn't in SourceMap.
		return 0, false
	}
	if i == len(shardIDs)-1 {
		// there are no more shards to iterate over.
		return 0, false
	}
	return shardIDs[i+1], true
}

// sortedSources returns the map keys, sorted low to high.
func sortedKeys(sources SourceMap) []int64 {
	shardIDs := make(int64Slice, 0, len(sources))
	for id := range sources {
		shardIDs = append(shardIDs, id)
	}
	sort.Sort(shardIDs)
	return shardIDs
}

type int64Slice []int64

func (p int64Slice) Len() int           { return len(p) }
func (p int64Slice) Less(i, j int) bool { return p[i] < p[j] }
func (p int64Slice) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
