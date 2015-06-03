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

package status

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	context "golang.org/x/net/context"
	codespb "github.com/google/key-server-transparency/proto/codes"
)

// Code is a status code.
type Code int

const (
	OK                 = Code(codespb.Code_OK)
	Canceled           = Code(codespb.Code_CANCELLED)
	Unknown            = Code(codespb.Code_UNKNOWN)
	InvalidArgument    = Code(codespb.Code_INVALID_ARGUMENT)
	DeadlineExceeded   = Code(codespb.Code_DEADLINE_EXCEEDED)
	NotFound           = Code(codespb.Code_NOT_FOUND)
	AlreadyExists      = Code(codespb.Code_ALREADY_EXISTS)
	PermissionDenied   = Code(codespb.Code_PERMISSION_DENIED)
	Unauthenticated    = Code(codespb.Code_UNAUTHENTICATED)
	ResourceExhausted  = Code(codespb.Code_RESOURCE_EXHAUSTED)
	FailedPrecondition = Code(codespb.Code_FAILED_PRECONDITION)
	Aborted            = Code(codespb.Code_ABORTED)
	OutOfRange         = Code(codespb.Code_OUT_OF_RANGE)
	Unimplemented      = Code(codespb.Code_UNIMPLEMENTED)
	Internal           = Code(codespb.Code_INTERNAL)
	Unavailable        = Code(codespb.Code_UNAVAILABLE)
	DataLoss           = Code(codespb.Code_DATA_LOSS)
)

func (c Code) String() string {
	return codespb.Code(c).String()
}

type Status struct {
	Code Code
	Msg           string                  // additional text detail
}

var zero Status

func nilToZero(s *Status) *Status {
	if s == nil {
		return &zero
	}
	return s
}

type statusError Status

func (s *statusError) Error() string {
	return (*Status)(s).String()
}

// Err returns nil if s is a successful status.  Otherwise it returns a value
// whose Error method returns st.String.
func (s *Status) Err() error {
	if s == nil || s.Code == 0 {
		return nil
	}
	return (*statusError)(s)
}

// FromError converts err to a *Status if err was created using (*Status).Err.
// It returns nil, false if the error does not correspond to any *Status.
// FromError(nil) returns (*Status)(nil), true.
func FromError(err error) (*Status, bool) {
	switch x := err.(type) {
	case nil:
		return nil, true
	case *statusError:
		return (*Status)(x), true
	}
	return nil, false
}

// Equal reports whether s and t have the same Space and Code.
// It does not compare the Msg or MessageSet details.
func (s *Status) Equal(t *Status) bool {
	s = nilToZero(s)
	t = nilToZero(t)
	return s.Code == t.Code 
}

func (s *Status) Canonical() *Status {
	return s
}

// New returns a *Status wiht the given code and message.
func New(c Code, msg string) *Status {
	return &Status{Code: c, Msg: msg}
}

// Error returns New(c, msg).Err().
func Error(c Code, msg string) error {
	return New(c, msg).Err()
}

// Newf constructs a *Status with a message built from a format string.
func Newf(c Code, format string, a ...interface{}) *Status {
	return New(c, fmt.Sprintf(format, a...))
}

// Errorf returns Newf(c, format, a...).Err().
func Errorf(c Code, format string, a ...interface{}) error {
	return Newf(c, format, a...).Err()
}

// convertCode converts a standard Go error into a canonical code.
func convertCode(err error) Code {
	switch err {
	case io.EOF:
		return OutOfRange
	case io.ErrClosedPipe, io.ErrNoProgress, io.ErrShortBuffer, io.ErrShortWrite, io.ErrUnexpectedEOF:
		return FailedPrecondition
	case os.ErrInvalid:
		return InvalidArgument
	case context.Canceled:
		return Canceled
	case context.DeadlineExceeded:
		return DeadlineExceeded
	}
	switch {
	case os.IsExist(err):
		return AlreadyExists
	case os.IsNotExist(err):
		return NotFound
	case os.IsPermission(err):
		return PermissionDenied
	}
	return Unknown
}

// Canonical converts an error into a status.
func Canonical(err error) *Status {
	if err == nil {
		return nil
	}
	if st, ok := FromError(err); ok {
		return st.Canonical()
	}
	var code Code
	if pe, ok := err.(*os.PathError); ok {
		if st, ok := FromError(pe.Err); ok {
			code = st.Code
		} else {
			code = convertCode(pe.Err)
		}
	} else {
		code = convertCode(err)
	}
	return &Status{Code: code, Msg: err.Error()}
}

// CanonicalCode converts an error into the matching canonical status code.
// It is equivalent to Canonical(err).CanonicalCode().
func CanonicalCode(err error) Code {
	switch e := err.(type) {
	case nil:
		return OK
	case *statusError:
		return e.Code
	}
	return convertCode(err)
}

// String returns the CodeText and the full status message.
func (s *Status) String() string {
	if s == nil || s.Msg == "" {
		return s.ShortString()
	}
	return s.ShortString() + ": " + s.Msg
}

// ShortString returns a shortened form of the status, like that returned by
// String but without the message.  
func (s *Status) ShortString() string {
	if s == nil || s.Code == 0 {
		return "OK"
	}
	text := s.CodeText(s.Code)
	if text == "" {
		text = strconv.Itoa(int(s.Code))
	}
	return text
}

// Reset clears the status s.
func (s *Status) Reset() {
	*s = Status{}
}

func (sp *Status) CodeText(code Code) string {
	if code == 0 {
		return "OK"
	}
	name := codespb.Code_name[int32(code)]
	if name != "" {
		return strings.ToLower(name)
	}
	return strconv.Itoa(int(code))
}
