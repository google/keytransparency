// Copyright 2016 CoreOS, Inc.
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

import (
	"golang.org/x/net/context"

	v3 "github.com/coreos/etcd/clientv3"
	recipe "github.com/coreos/etcd/contrib/recipes"
	spb "github.com/coreos/etcd/storage/storagepb"
)

// dequeue returns Enqueue()'d elements in FIFO order. If the
// queue is empty, dequeue blocks until elements are available.
// dequeue may return the head element more than once.
func (q *Queue) dequeue(f func(val []byte) error) error {
	// TODO: fewer round trips by fetching more than one key
	resp, err := q.client.Get(q.ctx, q.keyPrefix, v3.WithFirstRev()...)
	if err != nil {
		return err
	}

	kv := getFirstKey(resp.Kvs)
	if err != nil {
		return err
	} else if kv != nil {
		if err := f(kv.Value); err != nil {
			// Don't delete, next dequeue will retrieve same item.
			return err
		}
		if _, err := deleteRevKey(q.client, string(kv.Key), kv.ModRevision); err != nil {
			return err
		}
		return nil
	} else if resp.More {
		// missed some items, retry to read in more
		return q.dequeue(f)
	}

	// nothing yet; wait on elements
	ev, err := recipe.WaitPrefixEvents(
		q.client,
		q.keyPrefix,
		resp.Header.Revision,
		[]spb.Event_EventType{spb.PUT})
	if err != nil {
		return err
	}
	if err := f(ev.Kv.Value); err != nil {
		return err
	}
	if _, err := deleteRevKey(q.client, string(ev.Kv.Key), ev.Kv.ModRevision); err != nil {
		return err
	}
	return nil
}

func getFirstKey(kvs []*spb.KeyValue) *spb.KeyValue {
	for _, k := range kvs {
		return k
	}
	return nil
}

// deleteRevKey deletes a key by revision, returning false if key is missing
func deleteRevKey(kv v3.KV, key string, rev int64) (bool, error) {
	cmp := v3.Compare(v3.ModRevision(key), "=", rev)
	req := v3.OpDelete(key)
	txnresp, err := kv.Txn(context.TODO()).If(cmp).Then(req).Commit()
	if err != nil {
		return false, err
	} else if !txnresp.Succeeded {
		return false, nil
	}
	return true, nil
}
