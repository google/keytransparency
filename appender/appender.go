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

package appender

import (
	"golang.org/x/net/context"
)

// Appender is an append only interface into a data structure.
type Appender interface {
	// Adds an object to the append-only data structure.
	Append(ctx context.Context, epoch int64, data []byte) error

	// Epoch retrieves a specific object.
	// Returns data and a serialized ct.SignedCertificateTimestamp
	Epoch(ctx context.Context, epoch int64) ([]byte, []byte, error)

	// Latest returns the latest object.
	// Returns epoch, data, and a serialized ct.SignedCertificateTimestamp
	Latest(ctx context.Context) (int64, []byte, []byte, error)
}
