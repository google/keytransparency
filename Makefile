# Copyright 2016 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# TODO: Makefile will be deleted once the repo is public. Check issue #411.

main: 
	go build ./cmd/keytransparency-server ./cmd/keytransparency-sequencer ./cmd/keytransparency-client ./cmd/keytransparency-delegate ./cmd/gen-test-vectors

mysql: 
	go build -tags mysql ./cmd/keytransparency-server ./cmd/keytransparency-sequencer ./cmd/keytransparency-client

client:
	go build ./cmd/keytransparency-client

# The list of returned packages might not be unique. Fortunately go test gets
# rid of duplicates.
test: main
	go test ./...

coverage: main
	go test ./... -cover

check:
	gometalinter ./...

presubmit: test check

proto:
	go generate ./...

clean:
	rm -f srv keytransparency-server keytransparency-sequencer keytransparency-client
	rm -rf infra*
