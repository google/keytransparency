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

// Package multi contains utilities for multiplexing io operations.
package multi

import (
	"errors"
	"fmt"
	"io"
)

// Writer contains a list of io.Writer objects. Its Write method tries to write to all of them, and aggregates
// the errors (if any of the write call fails).
type Writer interface {
	AddWriter(w io.Writer)
	Write(p []byte) (n int, err error)
}

// NewWriter returns an implementation of the multi.Writer interface
func NewWriter(w io.Writer) Writer {
	return &writer{
		writers: []io.Writer{w},
	}
}

type writer struct {
	writers []io.Writer
}

func (m *writer) Write(p []byte) (n int, err error) {
	if len(m.writers) == 0 {
		return 0, fmt.Errorf("tried to use a MultiIoWriter which does not contain any writers")
	}
	multiError := ""
	minBytesWritten := len(p)
	for _, w := range m.writers {
		n, err = w.Write(p)
		if err != nil {
			multiError += fmt.Sprintf("%v bytes written to %v: %v", n, w, err)
		}
		minBytesWritten = min(n, minBytesWritten)
	}

	return minBytesWritten, errors.New(multiError)
}

func (m *writer) AddWriter(w io.Writer) {
	m.writers = append(m.writers, w)
}

func min(a, b int) int {
	if a <= b {
		return a
	}
	return b
}
