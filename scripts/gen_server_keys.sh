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

COMMONNAME=""
ADDRESS=""
SUBJECT="/C=US"

while getopts d:a:s: option; do
    case "${option}" in
	d) COMMONNAME=${OPTARG};;
	a) ADDRESS=${OPTARG};;
	s) SAN_DNS=${OPTARG};;
	*) echo "usage: ./gen_server_keys.sh -d <domain> -a <ip_address> -s <san_extension_DNS>"; exit 1;;
    esac
done

if [[ -n "${COMMONNAME}" ]]; then
    SUBJECT="${SUBJECT}/CN=${COMMONNAME}"
fi

# TODO(ismail): make the IPs configurable as well
ALTNAMES="[alt_names]\nDNS.1=${SAN_DNS}\nDNS.2=localhost\nIP.1=0.0.0.0"
if [[ -n "${ADDRESS}" ]]; then
    ALTNAMES="${ALTNAMES}\nIP.2=${ADDRESS}"
fi
SANEXT="[SAN]\nbasicConstraints=CA:TRUE\nsubjectAltName=@alt_names\n\n${ALTNAMES}"

# Create output directory.
KT_DIR=$(go list -f '{{ .Dir }}' -m github.com/google/keytransparency)
mkdir -p "${KT_DIR}/genfiles"
cd "${KT_DIR}/genfiles"

# Generate TLS keys.
openssl genrsa -des3 -passout pass:xxxx -out server.pass.key 2048
( umask 377 && openssl rsa -passin pass:xxxx -in server.pass.key -out server.key )
rm -f server.pass.key
openssl req -new \
	-key server.key \
	-subj "${SUBJECT}" \
	-reqexts SAN \
	-config <(cat /etc/ssl/openssl.cnf \
		      <(printf "${SANEXT}")) \
	-out server.csr
openssl x509 -req -days 365 -in server.csr -signkey server.key \
	-out server.crt -extensions SAN \
	-extfile <(printf "${SANEXT}")
