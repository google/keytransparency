// Copyright 2017 Google Inc. All Rights Reserved.
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

package core

//go:generate protoc -I=. -I=$GOPATH/src/github.com/google/trillian/ -I=$GOPATH/src/github.com/googleapis/googleapis/ --go_out=,plugins=grpc:$GOPATH/src api/v1/keytransparency_proto/keytransparency.proto api/v1/keytransparency_proto/admin.proto api/v1/keytransparency_proto/mutations.proto
//go:generate protoc -I=. -I=$GOPATH/src/github.com/google/trillian/ -I=$GOPATH/src/github.com/googleapis/googleapis/ --grpc-gateway_out=logtostderr=true:. api/v1/keytransparency_proto/keytransparency.proto api/v1/keytransparency_proto/admin.proto api/v1/keytransparency_proto/mutations.proto

//go:generate protoc -I=. -I=$GOPATH/src/github.com/google/trillian/ -I=$GOPATH/src/github.com/googleapis/googleapis/ --go_out=,plugins=grpc:$GOPATH/src proto/sequencer_v1_grpc/sequencer_v1_grpc.proto
//go:generate protoc -I=. -I=$GOPATH/src/github.com/google/trillian/ -I=$GOPATH/src/github.com/googleapis/googleapis/ --grpc-gateway_out=logtostderr=true:. proto/sequencer_v1_grpc/sequencer_v1_grpc.proto

//go:generate protoc -I=. -I=$GOPATH/src/github.com/google/trillian/ -I=$GOPATH/src/github.com/googleapis/googleapis/ --go_out=,plugins=grpc:$GOPATH/src api/monitor/v1/monitor_proto/monitor.proto
//go:generate protoc -I=. -I=$GOPATH/src/github.com/google/trillian/ -I=$GOPATH/src/github.com/googleapis/googleapis/ --grpc-gateway_out=logtostderr=true:. api/monitor/v1/monitor_proto/monitor.proto

//go:generate protoc -I=. -I=$GOPATH/src/github.com/google/trillian/ -I=$GOPATH/src/github.com/googleapis/googleapis --go_out=:$GOPATH/src api/usermanager/v1/usermanager_proto/usermanager.proto
//go:generate protoc -I=. -I=$GOPATH/src/github.com/google/trillian/ -I=$GOPATH/src/github.com/googleapis/googleapis/ --go_out=,plugins=grpc:$GOPATH/src api/usermanager/v1/usermanager_proto/usermanager.proto
//go:generate protoc -I=. -I=$GOPATH/src/github.com/google/trillian/ -I=$GOPATH/src/github.com/googleapis/googleapis/ --grpc-gateway_out=logtostderr=true:. api/usermanager/v1/usermanager_proto/usermanager.proto

//go:generate protoc -I=. -I=$GOPATH/src/github.com/google/trillian/ -I=$GOPATH/src/github.com/googleapis/googleapis --go_out=:$GOPATH/src api/type/type_proto/type.proto api/type/type_proto/keymaster.proto api/type/type_proto/authz.proto
