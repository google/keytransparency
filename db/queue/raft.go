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

package queue

type raftQueue struct {
	proposeC    chan string
	confChangeC chan raftpb.ConfChange
	commitC     <-chan string
	errorC      <-chan error
}

func NewRaftQueue(peers []string, id int, join bool) Queuer {
	r := &raftQueue{
		proposeC:    make(chan string),
		confChangeC: make(chan raftpb.ConfChange),
	}

	// raft provides a commit stream for the proposals
	r.commitC, r.errorC = newRaftNode(id, peers, join, r.proposeC, r.confChangeC)

	// exit when raft goes down
	go func() {
		if err, ok := <-r.errorC; ok {
			log.Fatal(err)
		}
	}()
}

func (r *raftQueue) Close() {
	defer close(r.proposeC)
	defer close(r.confChangeC)
}

func (r *raftQueue) Queue(ctx context.Context, k, v []byte) error {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(kv{k, v}); err != nil {
		return err
	}
	r.proposeC <- string(buf.Bytes())
}

// TODO: does this need to be in a go routine?
func (r *raftQueue) Dequeue() <-chan *Mutation {
	for data := range r.commitC {
		// TODO: can data be nil?
		var data_kv kv
		dec := gob.NewDecoder(bytes.NewBufferString(*data))
		if err := dec.Decode(&data_kv); err != nil {
			log.Fatalf("raftexample: could not decode message (%v)", err)
		}
		// TODO: push on output channel
	}
	if err, ok := <-r.errorC; ok {
		log.Fatal(err)
	}
}
