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

KTURLDEFAULT="35.184.134.53:8080"

# TODO(ismail): fetch the keys from the discovery API (#672)
##################################
##### Collecting information #####
##################################

cd "${GOPATH}/src/github.com/google/keytransparency"
printf "%s\n" "" > .keytransparency.yaml

read -p "Key Transparency URL and port, i.e. url:port, (default=${KTURLDEFAULT}): " KTURL
if [[ -z "${KTURL}" ]]; then
    KTURL="${KTURLDEFAULT}"
fi
printf "kt-url: %s\n" "${KTURL}" >> .keytransparency.yaml

read -p "Key Transparency gRPC/HTTPs certificate: " KTCERT
if [[ -n "${KTKEY}" ]]; then
    printf "kt-cert: %s\n" "${KTCERT}" >> .keytransparency.yaml
fi

read -p "Key Transparency VRF verification key: " VRF
if [[ -n "${VRF}" ]]; then
    printf "vrf: %s\n" "${VRF}" >> .keytransparency.yaml
fi

read -p "Trillian Log verification key: " LOGKEY
if [[ -n "${SIGKEY}" ]]; then
    printf "log-key: %s\n" "${LOGKEY}" >> .keytransparency.yaml
fi

read -p "Trillian Map verification key: " MAPKEY
if [[ -n "${MAPKEY}" ]]; then
    printf "map-key: %s\n" "${LOGKEY}" >> .keytransparency.yaml
fi

read -p "Path to client secret file: " CLIENTSECRET
printf "client-secret: %s\n" "${CLIENTSECRET}" >> .keytransparency.yaml

read -p "Path to service key file: " SERVICEKEY
printf "service-key: %s\n" "${SERVICEKEY}" >> .keytransparency.yaml

