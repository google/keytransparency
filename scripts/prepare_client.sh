#!/bin/bash

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

VRFDEFAULT="keys/test_verification_keys/vrf-pubkey.pem"
VRF=""
KTKEYDEFAULT="keys/test_verification_keys/server.crt"
KTKEY=""
SIGKEYDEFAULT="keys/test_verification_keys/p256-pubkey.pem"
SIGKEY=""
DOMAINDEFAULT="example.com"
DOMAIN=""
KTURLDEFAULT="104.199.112.76:5001"
KTURL=""
CLIENTSECRET=""

##################################
##### Collecting information #####
##################################

read -p "Key Transparency VRF verification key (default=${VRFDEFAULT}): " VRF
if [[ -z "${VRF}" ]]; then
    VRF="${VRFDEFAULT}"
fi

read -p "Key Transparency gRPC/HTTPs certificate (default=${KTKEYDEFAULT}): " KTKEY
if [[ -z "${KTKEY}" ]]; then
    KTKEY="${KTKEYDEFAULT}"
fi

read -p "Key Transparency signature verification key (default=${SIGKEYDEFAULT}): " SIGKEY
if [[ -z "${SIGKEY}" ]]; then
    SIGKEY="${SIGKEYDEFAULT}"
fi

read -p "Key Transparency domain name (default=${DOMAINDEFAULT}): " DOMAIN
if [[ -z "${DOMAIN}" ]]; then
    DOMAIN="${DOMAINDEFAULT}"
fi

read -p "Key Transparency URL and port, i.e. url:port, (default=${KTURLDEFAULT}): " KTURL
if [[ -z "${KTURL}" ]]; then
    KTURL="${KTURLDEFAULT}"
fi

read -p "Path to client secret file: " CLIENTSECRET


#####################
##### Executing #####
#####################

cd "${GOPATH}/src/github.com/google/key-transparency"

# Building binaries.
go build ./cmd/key-transparency-client

# Generate .key-transparency.yaml file.
KTYAML="ct-key: \"../certificate-transparency/test/testdata/ct-server-key-public.pem\"
ct-url: \"http://107.178.246.112\"
vrf:    \"${VRF}\"
kt-key: \"${KTKEY}\"
kt-sig: \"${SIGKEY}\"
domain: \"${DOMAIN}\"
kt-url: \"${KTURL}\"
client-secret: \"${CLIENTSECRET}\""

printf "%s\n" "${KTYAML}" > .key-transparency.yaml
