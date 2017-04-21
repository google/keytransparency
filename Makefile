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
# Package authentication implements authentication mechanisms.
#
# The Transparent Key Server is designed to be used by identity providers -
# IdP in OAuth parlance.  OAuth2 Access Tokens may be provided as
# authentication information, which can be resolved to user information and
# associated scopes on the backend.

# TODO: Makefile will be deleted once the repo is public. Check issue #411.

main: client
	go build ./cmd/keytransparency-server
	go build ./cmd/keytransparency-signer

mysql: client
	go build -tags mysql ./cmd/keytransparency-server
	go build -tags mysql ./cmd/keytransparency-signer

client:
	go build ./cmd/keytransparency-client

# The list of returned packages might not be unique. Fortunately go test gets
# rid of duplicates.
test: main
	go test `find . | grep '_test\.go$$' | sort | xargs -n 1 dirname`

coverage: main
	go test -cover `find . | grep '_test\.go$$' | sort | xargs -n 1 dirname`

fmt:
	find . -iregex '.*.go' ! -path "./vendor/*" -exec gofmt -s -w {} \;
	find . -iregex '.[^.]*.go' ! -path "./vendor/*" -exec golint {} \;

tools:
	-go vet ./cmd/... ./core/... ./impl/... ./integration/...
	find . ! -path "*/proto/*" ! -iwholename "*.git*" ! -iwholename "." ! -iwholename "*vendor*" -type d ! -name "proto" -exec errcheck -ignore 'Close|Write|Serve,os:Remove' {} \;
	-find . -type f -name "*.go" ! -path "./vendor/*" ! -name "*.pb*go" -exec gocyclo -over 15 {} \;
	-ineffassign .
	-find . -type f -name '*.md' ! -path "./vendor/*" -o -name '*.go' ! -path "./vendor/*" -o -name '*.proto' ! -path "./vendor/*" | sort | xargs misspell -locale US

presubmit: coverage fmt tools

travis-presubmit: fmt tools

proto:
	go generate ./...

clean:
	rm -f srv keytransparency-server keytransparency-signer keytransparency-client
	rm -rf infra*
