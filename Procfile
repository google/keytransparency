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

# Use goreman to run `go get github.com/mattn/goreman`
etcd1: etcd --name infra1 --listen-client-urls $LISTEN1 --advertise-client-urls $LISTEN1 --listen-peer-urls $PEER1 --initial-advertise-peer-urls $PEER1 --enable-pprof 
etcd2: etcd --name infra2 --listen-client-urls $LISTEN2 --advertise-client-urls $LISTEN2 --listen-peer-urls $PEER2 --initial-advertise-peer-urls $PEER2 --enable-pprof
etcd3: etcd --name infra3 --listen-client-urls $LISTEN3 --advertise-client-urls $LISTEN3 --listen-peer-urls $PEER3 --initial-advertise-peer-urls $PEER3 --enable-pprof
web: ./key-transparency-server --port=$PORT --key=$KEY --cert=$CERT --domain=$DOMAIN --db=$DB --maplog=$CTLOG --etcd=$LISTEN --vrf=$VRF_PRIV
sign: ./key-transparency-signer --domain=$DOMAIN --db=$DB  --maplog=$CTLOG --etcd=$LISTEN --period=$SIGN_PERIOD_SEC --key=$SIGN_KEY
