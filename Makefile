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

#include $(GOHOME)/src/pkg/github.com/golang/protobuf/Make.protobuf
DEPS:= $(shell find . -type f -name '*.proto' | sed 's/proto$$/pb.go/')
GATEWAY_DEPS:= $(shell find . -type f -name '*.proto' | sed 's/proto$$/pb.gw.go/')

main: proto
	go build -o key-transparency ./cmd/frontend
	go build -o key-transparency-signer ./cmd/backend
	go build -o key-transparency-client ./cmd/client

# The list of returned packages might not be unique. Fortunately go test gets
# rid of duplicates.
test: main
	go test `find . | grep '_test\.go$$' | sort | xargs -n 1 dirname`

coverage: main
	go test -cover `find . | grep '_test\.go$$' | sort | xargs -n 1 dirname`

fmt:
	find . -iregex '.*.go' -exec gofmt -w {} \;
	find . -iregex '.[^.]*.go' -exec golint {} \;

presubmit: coverage fmt
	-go vet ./...
	find . ! -path "*/proto/*" -not -iwholename "*.git*" -not -iwholename "." -type d ! -name "proto" -exec errcheck -ignore 'Close|Write,os:Remove,google.golang.org/grpc:Serve' {} \;
	-find . -type f -name "*.go" ! -name "*.pb*go" -exec gocyclo -over 12 {} \;
	-ineffassign .
	-find . -type f -name '*.md' -o -name '*.go' -o -name '*.proto' | sort | xargs misspell -locale US

proto:
	go generate ./...

clean:
	rm -f $(DEPS)
	rm -f $(GATEWAY_DEPS)
	$(MAKE) -C testdata clean
	rm -f srv key-transparency key-transparency-signer 
	rm -rf infra*

