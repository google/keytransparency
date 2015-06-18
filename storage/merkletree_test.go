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
	"fmt"
	"github.com/syndtr/goleveldb/leveldb"
	"io/ioutil"
	// "math/rand"
	"os"
	// "path/filepath"
	"testing"
)

func withDB(f func(*leveldb.DB)) {
	dir, err := ioutil.TempDir("", "merkletree")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	db, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		panic(err)
	}
	defer db.Close()
	f(db)
}

func TestOneEntry(t *testing.T) {
	withDB(func(db *leveldb.DB) {
		m := &MerkleTree{db}
		e := m.GetEpoch(1)
		index := []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
		val1, ep1, proofix, proof1, err := e.Lookup(index)
		if val1 != nil || ep1 != 0 || proofix != nil || proof1 != nil || err != nil {
			panic("bad lookup in empty tree")
		}
		val2 := []byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2}
		ne, err := e.AdvanceEpoch()
		if err != nil {
			panic(err)
		}
		err = ne.Set(index, val2)
		if err != nil {
			panic(err)
		}
		wb := new(leveldb.Batch)
		ne.Flush(wb)
		err = db.Write(wb, nil)
		if err != nil {
			panic(err)
		}
		e2 := m.GetEpoch(2)
		v, _, pix, _, err := e2.Lookup(index)
		if err != nil {
			panic(err)
		}
		if pix != nil {
			v = nil
		}
		if !bytes.Equal(v, val2) {
			panic(fmt.Errorf("Value mismatch: %x / %x", v, val2))
		}
		// TODO: verify proof
	})
}

func TestTwoEntriesOneEpoch(t *testing.T) {
	withDB(func(db *leveldb.DB) {
		m := &MerkleTree{db}
		e := m.GetEpoch(1)
		index := []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
		val := []byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2}
		ne, err := e.AdvanceEpoch()
		if err != nil {
			panic(err)
		}
		err = ne.Set(index, val)
		if err != nil {
			panic(err)
		}
		// Make sure mutating the slices afterwards is okay
		index[15]++
		val[15]++
		err = ne.Set(index, val)
		if err != nil {
			panic(err)
		}
		wb := new(leveldb.Batch)
		ne.Flush(wb)
		err = db.Write(wb, nil)
		if err != nil {
			panic(err)
		}
		e2 := m.GetEpoch(2)
		for i := 0; i < 2; i++ {
			v, _, pix, _, err := e2.Lookup(index)
			if err != nil {
				panic(err)
			}
			if pix != nil {
				v = nil
			}
			if !bytes.Equal(v, val) {
				panic(fmt.Errorf("Value mismatch: %x vs %x", v, val))
			}
			// TODO: verify proof
			index[15]--
			val[15]--
		}
	})
}

func TestThreeEntriesThreeEpochs(t *testing.T) {
	withDB(func(db *leveldb.DB) {
		m := &MerkleTree{db}
		indices := [][]byte{
			[]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
			[]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0},
			[]byte{0xf0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
		}
		values := [][]byte{
			[]byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
			[]byte{3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3},
			[]byte{4, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 4},
		}
		for i := 0; i < len(indices); i++ {
			e := m.GetEpoch(int64(i + 1))
			ne, err := e.AdvanceEpoch()
			if err != nil {
				panic(err)
			}
			err = ne.Set(indices[i], values[i])
			if err != nil {
				panic(err)
			}
			wb := new(leveldb.Batch)
			ne.Flush(wb)
			err = db.Write(wb, nil)
			if err != nil {
				panic(err)
			}
			for j := 0; j <= i+1; j++ {
				e2 := m.GetEpoch(int64(j + 1))
				for k := 0; k < len(indices); k++ {
					v, _, pix, _, err := e2.Lookup(indices[k])
					if err != nil {
						panic(err)
					}
					if pix != nil {
						v = nil
					}
					if k < j {
						if !bytes.Equal(v, values[k]) {
							panic(fmt.Errorf("Value mismatch: %x / %x", v, values[k]))
						}
						// TODO: verify proof
					} else {
						if v != nil {
							if !bytes.Equal(v, values[k]) {
								panic(fmt.Errorf("bled value mismatch: %d into %d; %x / %x", i, j, v, values[k]))
							} else {
								panic(fmt.Errorf("epoch bled: %d into %d", i, j))
							}
						}
					}
				}
			}
		}
	})
}
