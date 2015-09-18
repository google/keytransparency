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

package queue

import (
	"testing"
)

var (
	elements = []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
)

type Env struct {
	q *Queue
}

func NewEnv() *Env {
	return &Env{New()}
}

func (env *Env) fillQueue() {
	for _, v := range elements {
		env.q.Enqueue(v)
	}
}

func TestSize(t *testing.T) {
	env := NewEnv()
	if got, want := env.q.Size(), 0; got != want {
		t.Errorf("Queue size is %v, want %v", got, want)
	}

	env.fillQueue()
	if got, want := env.q.Size(), len(elements); got != want {
		t.Errorf("Queue size is %v, want %v", got, want)
	}
}

func TestDequeue(t *testing.T) {
	env := NewEnv()
	env.fillQueue()

	tests := []struct {
		element int
		size    int
		isNil   bool
	}{
		{0, 9, false},
		{1, 8, false},
		{2, 7, false},
		{3, 6, false},
		{4, 5, false},
		{5, 4, false},
		{6, 3, false},
		{7, 2, false},
		{8, 1, false},
		{9, 0, false},
		{0, 0, true},
	}

	for i, test := range tests {
		v := env.q.Dequeue()
		if got, want := (v == nil), test.isNil; got != want {
			t.Fatalf("Test[%v]: Dequeue returns nil = %v, want %v", i, got, want)
		}
		if v == nil {
			continue
		}

		if got, want := v, test.element; got != want {
			t.Errorf("Test[%v]: Dequeue() = %v, want %v", i, got, want)
		}

		if got, want := env.q.Size(), test.size; got != want {
			t.Errorf("Test[%v]: Size() = %v, want %v", i, got, want)
		}
	}
}

func TestPeek(t *testing.T) {
	env := NewEnv()
	env.fillQueue()

	tests := []struct {
		element int
		size    int
		isNil   bool
	}{
		{0, 10, false},
		{1, 9, false},
		{2, 8, false},
		{3, 7, false},
		{4, 6, false},
		{5, 5, false},
		{6, 4, false},
		{7, 3, false},
		{8, 2, false},
		{9, 1, false},
		{0, 0, true},
	}

	for i, test := range tests {
		v := env.q.Peek()
		if got, want := (v == nil), test.isNil; got != want {
			t.Fatalf("Test[%v]: Dequeue returns nil = %v, want %v", i, got, want)
		}
		if v == nil {
			continue
		}

		if got, want := v, test.element; got != want {
			t.Errorf("Test[%v]: Peek() = %v, want %v", i, got, want)
		}

		if got, want := env.q.Size(), test.size; got != want {
			t.Errorf("Test[%v]: Size() = %v, want %v", i, got, want)
		}

		env.q.Dequeue()
	}
}
