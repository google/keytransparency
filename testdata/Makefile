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

all: vrf tls sig

tls:
	openssl genrsa -des3 -passout pass:x -out server.pass.key 2048
	openssl rsa -passin pass:x -in server.pass.key -out server.key
	rm server.pass.key
	openssl req -new -key server.key -out server.csr \
		  -subj "/C=US/ST=CA/L=MountainView/CN=localhost"
	openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt

sig:
	openssl ecparam -name prime256v1 -genkey -noout -out p256-key.pem
	openssl ec -in p256-key.pem -pubout -out p256-pubkey.pem

vrf:
	openssl ecparam -name prime256v1 -genkey -noout -out vrf-key.pem
	openssl ec -in vrf-key.pem -pubout -out vrf-pubkey.pem

clean:
	find . -type f ! -name 'Makefile' -exec rm -f '{}' \;
