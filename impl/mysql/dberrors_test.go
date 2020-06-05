// Copyright 2020 Google Inc. All Rights Reserved.
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

package mysql

import (
	"fmt"
	"testing"

	"github.com/go-sql-driver/mysql"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestIsDeadlock(t *testing.T) {
	for _, test := range []struct {
		err  error
		want bool
	}{
		{want: false, err: nil},
		{want: false, err: fmt.Errorf("foobar")},
		{want: false, err: status.Errorf(codes.PermissionDenied, "denied")},
		{want: true, err: &mysql.MySQLError{Number: 1213, Message: "deadlock"}},
		{want: true, err: fmt.Errorf("wrapped: %w", &mysql.MySQLError{Number: 1213, Message: "deadlock"})},
		// gRPC errors don't support error wrapping.
		{want: false, err: status.Errorf(codes.PermissionDenied, "not wrapped: %v", &mysql.MySQLError{Number: 1213, Message: "deadlock"})},
	} {
		if got := IsDeadlock(test.err); got != test.want {
			t.Errorf("IsDeadlock(%v): %v, want %v", test.err, got, test.want)
		}
	}
}
