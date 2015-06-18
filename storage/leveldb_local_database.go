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
	"math"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"

	pb "github.com/google/e2e-key-server/proto/v2"
)

const (
	EPOCH_PREFIX       = 'E'
	LEAF_DELIMITER     = 'L'
	TREE_PREFIX        = 'T'
	NODE_KEY_DELIMITER = 'N'
)

type LocalLevelDB struct {
	db *leveldb.DB
}

func (l *LocalLevelDB) GetSTRByNumber(number int64) (*pb.SignedRoot, error) {
	key := serializeEpochKey(number)
	serialized, err := l.db.Get(key, nil)
	if err == leveldb.ErrNotFound {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	epoch := new(pb.SignedRoot)
	err = proto.Unmarshal(serialized, epoch)
	if err != nil {
		return nil, err
	}
	return epoch, nil
}

func (l *LocalLevelDB) GetLatestSTR() (str *pb.SignedRoot, err error) {
	iter := l.db.NewIterator(nil, nil)
	defer iter.Release()
	// TODO I'm not sure this will work okay if there are no keys past the seek
	// point. The documentation doesn't really say.
	iter.Seek(serializeEpochKey(math.MaxInt64))
	if iter.Prev() {
		str = new(pb.SignedRoot)
		proto.Unmarshal(iter.Value(), str)
		return
	} else {
		// No epochs exist yet
		return nil, nil
	}
}

// Read the newest version of an entry out of the local database, along with a proof
func (l *LocalLevelDB) ReadNewest(index []byte) (userProof *pb.UserProof, err error) {
	latestSTR, err := l.GetLatestSTR()
	if err != nil {
		return nil, err
	}
	return l.readAtSTR(latestSTR, index)
}

func (l *LocalLevelDB) readAtSTR(str *pb.SignedRoot, index []byte) (userProof *pb.UserProof, err error) {
	userProof = new(pb.UserProof)
	commitment, entryint64, proofIndex, neighbors, err :=
		AccessMerkleTree(l.db).GetEpoch(str.Epoch.EpochNr).Lookup(index)
	userProof.Proof = &pb.Proof{
		Neighbors: neighbors,
		Epoch:     str,
		Vuf:       index,
	}
	if err != nil {
		return nil, err
	}
	if commitment == nil {
		// Absence proof case 1: We've hit an empty branch
		userProof.User = nil
	} else if proofIndex != nil {
		// Absence proof case 2: We've hit a mismached leaf
		userProof.User = nil
		userProof.Proof.ExistingVuf = proofIndex
		userProof.Proof.ExistingCommitment = commitment
	} else {
		// The leaf actually exists
		userProof.User, err = l.lookupEntry(entryint64, index)
		if err != nil {
			return nil, err
		}
		userProof.Proof.ExistingVuf = index
		userProof.Proof.ExistingCommitment = commitment
	}
	return
}

// Read the entire history of versions of an entry, along with proofs for each version
func (l *LocalLevelDB) ReadHistoric(index []byte, startingAt int64) (userProofs []*pb.UserProof, err error) {
	iter := l.db.NewIterator(&util.Range{
		serializeLeafKey(startingAt, index),
		serializeLeafKey(int64(math.MaxInt64), index),
	}, nil)
	for iter.Next() {
		epochNr, ix := deserializeLeafKey(iter.Key())
		if !bytes.Equal(index, ix) {
			panic(fmt.Errorf("bad leaf in iterator: wanted %x; got %x", index, ix))
		}
		str, err := l.GetSTRByNumber(epochNr)
		userProof, err := l.readAtSTR(str, index)
		if err != nil {
			return nil, err
		}
		userProofs = append(userProofs, userProof)
	}
	return
}

// Create a new epoch, applying the given updates
func (l *LocalLevelDB) AdvanceEpoch(time time.Time, updates []*Update) (*pb.Epoch, error) {
	panic("unimplemented")
}

// Get the updates that made an epoch differ from its predecessor
func (l *LocalLevelDB) GetEpochUpdates(epoch int64) ([]Update, error) {
	panic("unimplemented")
}

// Read the version of an entry that was *set* in this particular epoch
func (l *LocalLevelDB) lookupEntry(epoch int64, index []byte) (user *pb.User, err error) {
	serialized, err := l.db.Get(serializeLeafKey(epoch, index), nil)
	if err != nil {
		return
	}
	user = new(pb.User)
	proto.Unmarshal(serialized, user)
	return
}

func serializeEpochKey(epoch int64) []byte {
	key := make([]byte, 1+8)
	key[0] = EPOCH_PREFIX
	// Use big-endian to make lexicographical order correspond to epoch order
	binary.BigEndian.PutUint64(key[1:], uint64(epoch))
	return key
}

func deserializeEpochKey(key []byte) int64 {
	if len(key) != 1+8 || key[0] != EPOCH_PREFIX {
		panic(fmt.Errorf("bad epoch key: %x", key))
	}
	return int64(binary.BigEndian.Uint64(key[1:]))
}

func serializeLeafKey(epoch int64, index []byte) (key []byte) {
	if len(index) != INDEX_BYTES {
		panic(fmt.Errorf("bad index length: %x", index))
	}
	key = make([]byte, 0, 1+INDEX_BYTES+1+8)
	key = append(key, TREE_PREFIX)
	key = append(key, index...)
	key = append(key, LEAF_DELIMITER)
	// Use big-endian to make lexicographical order correspond to epoch order
	binary.BigEndian.PutUint64(key[len(key):len(key)+8], uint64(epoch))
	key = key[:len(key)+8]
	return
}

func deserializeLeafKey(key []byte) (epoch int64, index []byte) {
	if len(key) != 1+INDEX_BYTES+1+8 {
		panic(fmt.Errorf("bad leaf key length: %x", key))
	}
	if key[0] != TREE_PREFIX {
		panic(fmt.Errorf("bad leaf prefix: %x", key))
	}
	index = key[1 : 1+INDEX_BYTES]
	if key[1+INDEX_BYTES] != LEAF_DELIMITER {
		panic(fmt.Errorf("bad leaf delimiter: %x", key))
	}
	epoch = int64(binary.BigEndian.Uint64(key[1+INDEX_BYTES+1:]))
	return
}
