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
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/syndtr/goleveldb/leveldb"
	// leveldbopt "github.com/syndtr/goleveldb/leveldb/opt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/google/e2e-key-server/crypto"
	"github.com/google/e2e-key-server/util"
)

const (
	INDEX_BYTES        = 32
	INDEX_BITS         = INDEX_BYTES * 8
	EPOCH_NR_BYTES     = 8
	INDEX_LENGTH_BYTES = 4
)

type MerkleTree struct {
	db *leveldb.DB
}

func AccessMerkleTree(db *leveldb.DB) *MerkleTree {
	return &MerkleTree{db}
}

type TreeEpoch struct {
	tree *MerkleTree
	nr   int64
}

type diskNode struct {
	isLeaf            bool
	childEpochNumbers [2]int64                   // 0 if the node is a leaf
	childHashes       [2][crypto.HASH_BYTES]byte // zeroed if the node is a leaf
	commitment        []byte                     // nil if the node is not a leaf
	indexBytes        []byte                     // nil if the node is not a leaf
}

type node struct {
	diskNode
	epoch      *TreeEpoch
	prefixBits []bool
	children   [2]*node // lazily loaded
}

type NewTreeEpoch struct {
	TreeEpoch
	root *node
}

func (tree *MerkleTree) GetEpoch(nr int64) *TreeEpoch {
	// TODO: This can't actually determine whether the epoch exists, since a missing entry might just
	// indicate an empty tree. Is that okay?
	return &TreeEpoch{tree, nr}
}

func (epoch *TreeEpoch) Lookup(indexBytes []byte) (
	commitment []byte, entryEpoch int64, proofIndex []byte, proof [][]byte, err error,
) {
	if len(indexBytes) != INDEX_BYTES {
		// TODO: is it actually sensible to return a grpc error from deep inside the internals?
		return nil, 0, nil, nil, grpc.Errorf(codes.InvalidArgument, "Wrong index length")
	}
	n, err := epoch.loadNode([]bool{}) // get root
	if err != nil {
		return
	}
	if n == nil {
		// Special case: The tree is empty
		return nil, 0, nil, nil, nil
	}
	indexBits := util.ToBits(INDEX_BITS, indexBytes)
	// Traverse down the tree, following either the left or right child depending on the next bit.
	for !n.isLeaf {
		descendingRight := indexBits[len(n.prefixBits)]
		siblingHash := n.childHashes[util.BitToIndex(!descendingRight)]
		proof = append(proof, siblingHash[:])
		childPointer, err := n.getChildPointer(descendingRight)
		if err != nil {
			return nil, 0, nil, nil, err
		}
		n = *childPointer
		if n == nil {
			// There's no leaf with this index. The proof will now function as a proof of absence to the
			// client by showing a valid hash path down to the nearest sibling, which creates the correct
			// root hash when this branch's hash is nil.
			return nil, 0, nil, proof, nil
		}
	}
	// Once a leaf node is reached, compare the entire index stored in the leaf node.
	if bytes.Equal(indexBytes, n.indexBytes) {
		// The leaf exists: we will simply return the value hash
	} else {
		// There is no leaf with the requested index. To prove it, we need to return the mismatching
		// leaf node along with its Merkle proof.
		proofIndex = append([]byte(nil), n.indexBytes...) // Copy the index bytes
	}
	return n.commitment, n.epoch.nr, proofIndex, proof, nil
}

// Creates a new epoch to be built up in memory (doesn't actually touch the disk
// yet)
func (epoch *TreeEpoch) AdvanceEpoch() (*NewTreeEpoch, error) {
	root, err := epoch.loadNode([]bool{})
	if err != nil {
		return nil, nil
	}
	newEpoch := &NewTreeEpoch{
		TreeEpoch{
			tree: epoch.tree,
			nr:   epoch.nr + 1,
		},
		root,
	}
	if root != nil {
		root.epoch = &newEpoch.TreeEpoch
	}
	return newEpoch, nil
}

// Updates the value hash at the index (or insert it if it did not exist).
// In-memory: doesn't actually touch the disk yet.
func (epoch *NewTreeEpoch) Set(indexBytes []byte, commitment []byte) (err error) {
	if len(indexBytes) != INDEX_BYTES {
		// TODO: is it actually sensible to return a grpc error from deep inside the internals?
		return grpc.Errorf(codes.InvalidArgument, "Wrong index length")
	}
	commitment = append([]byte(nil), commitment...) // Make a copy of commitment
	indexBits := util.ToBits(INDEX_BITS, indexBytes)
	nodePointer := &epoch.root
	position := 0
	// Traverse down the tree, following either the left or right child depending on the next bit.
	for *nodePointer != nil && !(*nodePointer).isLeaf {
		nodePointer, err = (*nodePointer).getChildPointer(indexBits[position])
		if err != nil {
			return err
		}
		position++
	}
	if *nodePointer == nil {
		// We've hit an empty branch where this leaf belongs -- put it there.
		*nodePointer = &node{
			diskNode: diskNode{
				isLeaf:     true,
				indexBytes: append([]byte(nil), indexBytes...), // Make a copy of indexBytes
				commitment: commitment,
			},
			prefixBits: indexBits[:position],
		}
		// flush will update the epoch numbers and hashes
	} else if bytes.Equal((*nodePointer).indexBytes, indexBytes) {
		// We have an existing leaf at this index; just replace the value
		(*nodePointer).commitment = commitment
		// flush will update the epoch numbers and hashes
	} else {
		// We have a different leaf with a matching prefix. We'll have to create new intermediate nodes.
		oldLeaf := *nodePointer
		oldLeafIndexBits := util.ToBits(INDEX_BITS, oldLeaf.indexBytes)
		for oldLeafIndexBits[position] == indexBits[position] {
			newNode := &node{
				diskNode: diskNode{
					isLeaf: false,
				},
				prefixBits: indexBits[:position],
			}
			// flush will set the epoch numbers and hashes
			*nodePointer, nodePointer = newNode, &newNode.children[util.BitToIndex(indexBits[position])]
			position++
		}
		splitNode := &node{
			diskNode: diskNode{
				isLeaf: false,
			},
			prefixBits: indexBits[:position],
		}
		newLeaf := &node{
			diskNode: diskNode{
				isLeaf:     true,
				indexBytes: append([]byte(nil), indexBytes...), // Make a copy of the index
				commitment: commitment,
			},
			prefixBits: indexBits[:position+1],
		}
		oldLeaf.prefixBits = oldLeafIndexBits[:position+1]
		splitNode.children[util.BitToIndex(indexBits[position])] = newLeaf
		splitNode.children[util.BitToIndex(oldLeafIndexBits[position])] = oldLeaf
		*nodePointer = splitNode
	}
	return nil
}

// Returns the new root hash
func (epoch *NewTreeEpoch) Flush(wb *leveldb.Batch) []byte {
	if epoch.root == nil {
		return make([]byte, crypto.HASH_BYTES)
	} else {
		hash := epoch.root.flush(&epoch.TreeEpoch, wb)
		return hash[:]
	}
}

//////// Node manipulation functions ////////

func (epoch *TreeEpoch) loadNode(prefixBits []bool) (*node, error) {
	nodeBytes, err := epoch.tree.db.Get(serializeKey(epoch.nr, prefixBits), nil)
	if err == leveldb.ErrNotFound {
		return nil, nil
	} else if err != nil {
		return nil, err
	} else {
		n := deserializeNode(nodeBytes)
		return &node{
			diskNode:   n,
			epoch:      epoch,
			prefixBits: prefixBits,
		}, nil
	}
}

// Write the updated nodes in the branch out to disk in the new epoch, returning the updated hash of
// the branch
func (n *node) flush(epoch *TreeEpoch, wb *leveldb.Batch) (hash [crypto.HASH_BYTES]byte) {
	for i := 0; i < 2; i++ {
		if n.children[i] != nil {
			n.childHashes[i] = n.children[i].flush(epoch, wb)
			n.childEpochNumbers[i] = epoch.nr
		}
	}
	n.epoch = epoch
	n.store(wb)
	copy(hash[:], n.hash())
	return
}

func (n *node) store(wb *leveldb.Batch) {
	wb.Put(serializeKey(n.epoch.nr, n.prefixBits), n.serialize())
}

func (n *node) getChildPointer(isRight bool) (**node, error) {
	ix := util.BitToIndex(isRight)
	if n.childEpochNumbers[ix] != 0 && n.children[ix] == nil {
		// lazy-load the child
		childIndex := append(n.prefixBits, isRight)
		childEpoch := n.epoch.tree.GetEpoch(n.childEpochNumbers[ix])
		child, err := childEpoch.loadNode(childIndex)
		if err != nil {
			return nil, err
		}
		n.children[ix] = child
	}
	return &n.children[ix], nil
}

func serializeKey(epoch int64, prefixBits []bool) []byte {
	indexBytes := util.ToBytes(prefixBits)
	key := make([]byte, 0, 1+len(indexBytes)+4+1+8)
	key = append(key, TREE_PREFIX)
	key = append(key, indexBytes...)
	binary.LittleEndian.PutUint32(key[len(key):len(key)+4], uint32(len(prefixBits)))
	key = key[:len(key)+4]
	key = append(key, NODE_KEY_DELIMITER)
	// Use big-endian to make lexicographical order correspond to epoch order
	binary.BigEndian.PutUint64(key[len(key):len(key)+8], uint64(epoch))
	key = key[:len(key)+8]
	return key
}

func (n *diskNode) serialize() []byte {
	if n.isLeaf {
		return append(append([]byte{crypto.LEAF_IDENTIFIER}, n.indexBytes...), n.commitment...)
	} else {
		buf := make([]byte, 1, 1+2*8+2*crypto.HASH_BYTES)
		buf[0] = crypto.INTERMEDIATE_NODE_IDENTIFIER
		for i := 0; i < 2; i++ {
			binary.LittleEndian.PutUint64(buf[len(buf):len(buf)+8], uint64(n.childEpochNumbers[i]))
			buf = buf[:len(buf)+8]
			buf = append(buf, n.childHashes[i][:]...)
		}
		return buf
	}
}

func deserializeNode(buf []byte) (n diskNode) {
	if buf[0] == crypto.LEAF_IDENTIFIER {
		n.isLeaf = true
		buf = buf[1:]
		n.indexBytes = buf[:INDEX_BYTES]
		buf = buf[INDEX_BYTES:]
		n.commitment = buf[:crypto.HASH_BYTES]
		buf = buf[crypto.HASH_BYTES:]
		if len(buf) != 0 {
			panic("bad leaf node length")
		}
	} else if buf[0] == crypto.INTERMEDIATE_NODE_IDENTIFIER {
		n.isLeaf = false
		buf = buf[1:]
		for i := 0; i < 2; i++ {
			n.childEpochNumbers[i] = int64(binary.LittleEndian.Uint64(buf[:8]))
			buf = buf[8:]
			copy(n.childHashes[i][:], buf[:crypto.HASH_BYTES])
			buf = buf[crypto.HASH_BYTES:]
		}
		if len(buf) != 0 {
			panic("bad intermediate node length")
		}
	} else {
		panic(fmt.Errorf("bad node identifier: %x", buf[0]))
	}
	return
}

func (n *node) hash() []byte {
	if n.isLeaf {
		return crypto.HashIntermediateNode(n.prefixBits, &n.childHashes)
	} else {
		return crypto.HashLeaf(n.indexBytes, n.commitment)
	}
}
