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

package storage

import (
	"crypto/sha256"
	"encoding/binary"
	"time"

	"github.com/google/e2e-key-server/crypto"
	"github.com/google/e2e-key-server/util"

	pb "github.com/google/e2e-key-server/proto/v2"
)

type MemEpoch struct {
	signedRoot *pb.SignedRoot
	contents   map[[crypto.HASH_BYTES]byte]*pb.User
	tree       *MemMerkleTree
}

type MemMerkleTree struct {
	root *Node
}

type Node struct {
	prefixBits  []bool
	children    [2]*Node
	childHashes [2][]byte
	index       *[INDEX_BYTES]byte
	commitment  []byte
}

type Entry struct {
	index      *[INDEX_BYTES]byte
	commitment []byte
}

func buildBranch(prefix []byte, prefixBitLen int, entries []Entry) *Node {
	if len(entries) == 0 {
		return nil
	} else if len(entries) == 1 {
		return &Node{
			index:      entries[0].index,
			commitment: entries[0].commitment,
		}
	} else {
		leftEntries := []Entry{}
		rightEntries := []Entry{}
		for _, entry := range entries {
			if entry.index[prefixBitLen/8]&(1<<uint(7-prefixBitLen%8)) == 0 {
				leftEntries = append(leftEntries, entry)
			} else {
				rightEntries = append(rightEntries, entry)
			}
		}
		n := new(Node)
		n.prefixBits = util.ToBits(prefixBitLen, prefix)
		if prefixBitLen%8 == 0 {
			prefix = append(prefix, 0)
		}
		prefix[prefixBitLen/8] &^= (1 << uint(7-prefixBitLen%8))
		n.children[0] = buildBranch(prefix, prefixBitLen+1, leftEntries)
		n.childHashes[0] = n.children[0].hash()
		prefix[prefixBitLen/8] |= 1 << uint(7-prefixBitLen%8)
		n.children[1] = buildBranch(prefix, prefixBitLen+1, rightEntries)
		n.childHashes[1] = n.children[1].hash()
		return n
	}
}

func int32ToBytes(i int) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, uint32(i))
	return buf
}

func (n *Node) hash() []byte {
	// Just for extra testing purposes, reimplement this off the spec in a simple, stupid way
	h := sha256.New()
	if n.index == nil {
		h.Write([]byte{'I'})
		h.Write(int32ToBytes(len(n.prefixBits)))
		h.Write(n.childHashes[0])
		h.Write(n.childHashes[1])
		h.Write(util.ToBytes(n.prefixBits))
	} else {
		h.Write([]byte{'L'})
		h.Write(n.index[:])
		h.Write(n.commitment)
	}
	return h.Sum(nil)
}

func (m *MemMerkleTree) lookup(index []byte) (found *Node, sideHashes [][]byte) {
	if m.root == nil {
		return nil, [][]byte{}
	} else {
		found = m.root.lookup(index, 0, &sideHashes)
		return
	}
}

func (n *Node) lookup(index []byte, pos int, sideHashes *[][]byte) (found *Node) {
	if n.index != nil {
		return n
	} else {
		var child *Node
		if index[pos/8]&(1<<uint(7-pos%8)) == 0 {
			*sideHashes = append(*sideHashes, n.childHashes[1])
			child = n.children[0]
		} else {
			*sideHashes = append(*sideHashes, n.childHashes[0])
			child = n.children[1]
		}
		if child == nil {
			return nil
		} else {
			return child.lookup(index, pos+1, sideHashes)
		}
	}
}

type MemLocalDB struct {
	epochs []*MemEpoch
}

func (l *MemLocalDB) GetSTRByNumber(number int64) (*pb.SignedRoot, error) {
	if number < int64(len(l.epochs)) {
		return l.epochs[number].signedRoot, nil
	} else {
		return nil, nil
	}
}

func (l *MemLocalDB) GetLatestSTR() (*pb.SignedRoot, error) {
	if len(l.epochs) == 0 {
		return nil, nil
	} else {
		return l.epochs[len(l.epochs)-1].signedRoot, nil
	}
}

func (l *MemLocalDB) ReadNewest(index []byte) (userProof *pb.UserProof, err error) {
	if len(l.epochs) == 0 {
		// TODO -- I guess the DB should be initialized with an empty tree at Epoch 1
		return nil, nil
	} else {
		latest := l.epochs[len(l.epochs)-1]
		return l.readAtEpoch(latest, index)
	}
}

func (l *MemLocalDB) readAtEpoch(epoch *MemEpoch, index []byte) (userProof *pb.UserProof, err error) {
	var indexArray [crypto.HASH_BYTES]byte
	copy(indexArray[:], index)
	userProof = new(pb.UserProof)
	userProof.User = epoch.contents[indexArray]
	userProof.Proof = new(pb.Proof)
	userProof.Proof.Vuf = index
	userProof.Proof.Epoch = epoch.signedRoot
	node, neighbors := epoch.tree.lookup(index)
	userProof.Proof.Neighbors = neighbors
	if node != nil {
		userProof.Proof.ExistingVuf = node.index[:]
		userProof.Proof.ExistingCommitment = node.commitment
	}
	return
}

func (l *MemLocalDB) ReadHistoric(index []byte, startingAt int64) (userProofs []*pb.UserProof, err error) {
	var lastValue *pb.User // need referential equality on these
	for epochNr := startingAt; epochNr < int64(len(l.epochs)); epochNr++ {
		result, _ := l.readAtEpoch(l.epochs[epochNr], index)
		if result.User != lastValue {
			lastValue = result.User
			userProofs = append(userProofs, result)
		}
	}
	return
}

func (l *MemLocalDB) AdvanceEpoch(time time.Time, updates []*Update) (*pb.Epoch, error) {
	panic("unimplemented")
}

// Get the updates that made an epoch differ from its predecessor
func (l *MemLocalDB) GetEpochUpdates(epoch int64) ([]Update, error) {
	panic("unimplemented")
}
