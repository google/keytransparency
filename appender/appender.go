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
// TODO: Make generic for CT.
type Appender interface {
	// Adds an objec to the append-only data structure.
	Append(ctx context.Context, timestamp int64, data []byte) error
	GetByIndex(ctx context.Context, index int64) ([]byte, error)
	GetByTimeStamp(ctx context.Context, timestamp int64) ([]byte, error)
	// GetHLast returns the hash of the previous item. Used for forming hash chains.
	GetHLast(ctx context.Context) ([]byte, error)
	// Latest returns the index of the current epoch.
	Latest(ctx context.Context) int64
}
