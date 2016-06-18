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

package client

import (
	"log"

	"github.com/golang/protobuf/proto"

	ctmap "github.com/gdbelvin/e2e-key-server/proto/security_ctmap"
)

func EpochHead(seh *ctmap.SignedEpochHead) (*ctmap.EpochHead, error) {
	eh := new(ctmap.EpochHead)
	if err := proto.Unmarshal(seh.EpochHead, eh); err != nil {
		log.Printf("Error unmarshaling epoch_head: %v", err)
		return nil, err
	}
	return eh, nil
}
