// Copyright 2019 Google Inc. All Rights Reserved.
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

// Package errors enumerates the possible errors of the sequencer pipeline.
package status

import (
	"fmt"

	"github.com/google/keytransparency/core/sequencer/codes"
	"google.golang.org/grpc/status"
)

type Status struct {
	code codes.Code
	msg  string
}

func (s *Status) Code() codes.Code { return s.code }
func (s *Status) Message() string  { return s.msg }
func (s *Status) Error() string    { return fmt.Sprintf("Code: %v, Message: %v", s.code, s.msg) }
func (s *Status) GRPCStatus() *status.Status {
	return status.New(s.code.GRPCCode(), s.Message())
}

func Wrap(s *Status, msg string) *Status {
	return &Status{code: s.code, msg: fmt.Sprintf("%v: %v", s.msg, msg)}
}

func Wrapf(s *Status, format string, a ...interface{}) *Status {
	return Wrap(s, fmt.Sprintf(format, a...))
}

func New(code codes.Code, msg string) *Status {
	return &Status{code: code, msg: msg}
}

func Newf(code codes.Code, format string, a ...interface{}) *Status {
	return New(code, fmt.Sprintf(format, a...))
}

func Errorf(code codes.Code, format string, a ...interface{}) error {
	return Newf(code, format, a...)
}

func FromError(err error) (*Status, bool) {
	if err == nil {
		return &Status{code: codes.OK}, true
	}
	if s, ok := err.(*Status); ok {
		return s, true
	}
	return New(codes.Unknown, err.Error()), false
}

func Convert(err error) *Status {
	s, _ := FromError(err)
	return s
}
