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

// package replace implements a simple replacement stragey as a mapper
package replace

import ()

// Replace defines mutations to simply replace the current map value with the
// contents of the mutation.
type Replace struct{}

func New() *Replace {
	return &Replace{}
}

// CheckMutation verifies that this is a valid mutation for this item.
func (r *Replace) CheckMutation(value, mutation []byte) error {
	return nil
}

// Mutate applies mutation to value
func (r *Replace) Mutate(value, mutation []byte) ([]byte, error) {
	return mutation, nil
}
