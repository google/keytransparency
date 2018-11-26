// Copyright 2018 Google Inc. All Rights Reserved.
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

package main

import (
	"context"
	"flag"
	"log"

	"github.com/apache/beam/sdks/go/pkg/beam"
	"github.com/apache/beam/sdks/go/pkg/beam/x/beamx"
	"github.com/google/keytransparency/cmd/serverutil"
	"github.com/google/keytransparency/core/sequencer/mapper"
)

var (
	serverDBPath = flag.String("db", "db", "Database connection string")
	mapURL       = flag.String("map-url", "", "URL of Trillian Map Server")
)

func main() {
	flag.Parse()

	mapper.SetDialer(serverutil.OpenSourceDialer{})

	beam.Init()

	args := mapper.Args{
		MapSpec: *mapURL,
		DBPath:  *serverDBPath,
	}

	p := args.Pipeline()

	if err := beamx.Run(context.Background(), p); err != nil {
		log.Fatalf("Failed to execute job: %v", err)
	}
}
