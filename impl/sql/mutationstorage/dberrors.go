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

package mutationstorage

import (
	"fmt"

	"github.com/mattn/go-sqlite3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// dbErrorf tries to extract a meaningful error code from err,
// the err returned from the database.
func dbErrorf(err error, format string, a ...interface{}) error {
	if err == nil {
		return nil
	}
	msg := fmt.Sprintf(format, a...)
	if st, ok := status.FromError(err); ok {
		return status.Errorf(st.Code(), "%v: %v", msg, st.Message())
	}
	if sqliteErr, ok := err.(sqlite3.Error); ok {
		code := codes.OK
		switch sqliteErr.Code {
		case sqlite3.ErrBusy:
			fallthrough
		case sqlite3.ErrLocked:
			code = codes.Aborted
		default:
			code = codes.Internal
		}
		return status.Errorf(code, "%v: %v", msg, err)
	}
	return status.Errorf(codes.Internal, "%v, unknown db engine err: %v", msg, err)
}
