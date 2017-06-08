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

package clock

import "time"

// System is a realtime clock
var System  = sysClock{}

// Time is a time source
type Time interface {
	Now() time.Time
	Since(time.Time) time.Duration
}

type sysClock struct{}

func (c sysClock) Now() time.Time {
	return time.Now()
}

func (c sysClock) Since(t time.Time) time.Duration {
	return time.Since(t)
}
