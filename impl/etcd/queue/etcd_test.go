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
	"errors"
	"testing"

	"github.com/coreos/etcd/integration"
)

var clusterSize = 3

func TestRetryOnFailure(t *testing.T) {
	c := integration.NewClusterV3(t, &integration.ClusterConfig{Size: clusterSize})
	defer c.Terminate(t)

	cli := c.RandClient()
	q := New(cli, "testID")

	insert := []struct {
		key   string
		value string
	}{
		{"1", "one"},
		{"2", "two"},
		{"3", "three"},
	}
	retrieve := []struct {
		key     string
		value   string
		success bool
	}{
		{"1", "one", true},
		{"2", "two", false},
		{"2", "two", true},
		{"3", "three", true},
	}
	for _, tc := range insert {
		if err := q.Enqueue([]byte(tc.key), []byte(tc.value)); err != nil {
			t.Errorf("Enqueue(%v, %v): %v", tc.key, tc.value, err)
		}
	}
	for _, tc := range retrieve {
		if got := nil == q.Dequeue(func(key, value []byte) error {
			if gotk, gotv := string(key), string(value); gotk != tc.key || gotv != tc.value {
				t.Errorf("Dequeue(): %v, %v, want %v, %v", gotk, gotv, tc.key, tc.value)
			}
			if !tc.success {
				return errors.New("fake commitment failure")
			}
			return nil
		}, nil); got != tc.success {
			t.Errorf("Dequeue(): %v, want %v", got, tc.success)
		}
	}
}
