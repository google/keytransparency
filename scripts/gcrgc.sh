#!/bin/bash

# Copyright © 2017 Google Inc.
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
# Souce: https://gist.github.com/ahmetb/7ce6d741bd5baa194a3fac6b1fec8bb7

IFS=$'\n\t'
set -eou pipefail

if [[ "$#" -ne 2 || "${1}" == '-h' || "${1}" == '--help' ]]; then
  cat >&2 <<"EOF"
gcrgc.sh cleans up tagged or untagged images pushed before specified date
for a given repository (an image name without a tag/digest).
USAGE:
  gcrgc.sh REPOSITORY DATE
EXAMPLE
  gcrgc.sh gcr.io/ahmet/my-app 2017-04-01
  would clean up everything under the gcr.io/ahmet/my-app repository
  pushed before 2017-04-01.
EOF
  exit 1
elif [[ "${#2}" -ne 10 ]]; then
  echo "wrong DATE format; use YYYY-MM-DD." >&2
  exit 1
fi

main(){
  local C=0
  IMAGE="${1}"
  DATE="${2}"
  for digest in $(gcloud container images list-tags ${IMAGE} --limit=999999 --sort-by=TIMESTAMP \
    --filter="timestamp.datetime < '${DATE}'" --format='get(digest)'); do
    (
      set -x
      gcloud container images delete -q --force-delete-tags "${IMAGE}@${digest}"
    )
    let C=C+1
  done
  echo "Deleted ${C} images in ${IMAGE}." >&2
}

main "${1}" "${2}"
