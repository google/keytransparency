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

// This package contains an implementation of a goroutine safe queue.
package queue

import (
	"container/list"
	"sync"
)

// Queue implements a goroutine safe queue.
type Queue struct {
	// list is the internal data structure of the queue.
	list *list.List
	// mu synchronizes access to list.
	mu sync.Mutex
}

// New creates an empty queue.
func New() *Queue {
	return &Queue{list.New(), sync.Mutex{}}
}

// Size returns the number of elements in the queue.
func (q *Queue) Size() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.list.Len()
}

// Enqueue adds an element at the end of the queue.
func (q *Queue) Enqueue(elem interface{}) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.list.PushBack(elem)
}

// Dequeue returns and deletes the element at the beginning of the queue.
func (q *Queue) Dequeue() interface{} {
	q.mu.Lock()
	defer q.mu.Unlock()

	result := q.list.Front()
	if result == nil {
		return nil
	}
	q.list.Remove(result)
	return result.Value
}

// Peek returns the element at the beginning of the queue without deleting it.
func (q *Queue) Peek() interface{} {
	q.mu.Lock()
	defer q.mu.Unlock()

	result := q.list.Front()
	if result == nil {
		return nil
	}
	return result.Value
}
