#!/usr/bin/env bash

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

# Create output directory.
KT_DIR=$(go list -f '{{ .Dir }}' -m github.com/google/keytransparency)
mkdir -p "${KT_DIR}/genfiles"
cd "${KT_DIR}/genfiles"

INTERACTIVE=1

while getopts ":f" opt; do
  case $opt in
    f)
      INTERACTIVE=0
      ;;
    \?)
      echo "Invalid option: -$OPTARG."
      usage
      exit 1
      ;;
  esac
done


DEFAULT_PWD=towel

# Generate monitor signing key-pair:
if ((INTERACTIVE == 1)); then
  # Prompts for password:
	( umask 377 && openssl ecparam -name prime256v1 -genkey | openssl ec -aes256 -out monitor_sign-key.pem)
else
	( umask 377 && openssl ecparam -name prime256v1 -genkey | openssl ec -aes256 -passout pass:$DEFAULT_PWD -out monitor_sign-key.pem )
fi

