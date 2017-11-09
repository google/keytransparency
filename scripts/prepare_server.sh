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

declare -i FRONTEND
declare -i FRONTENDNUM
declare -i BACKEND

# Initialize variables.
INTERACTIVE=1
FRONTEND=1
FRONTENDNUM=0
BACKEND=1
MONITOR=1
# 1 means SQLite, 2 means MySQL
DSN=""
IP1="127.0.0.1"
IP2="127.0.0.1"
IP3="127.0.0.1"
SERVICEKEY="service_key.json"
LISTENADDR=""
CERTDOMAIN=""
# Additional SAN extension domain and IP; besides localhost for local testing.
# (domain kt-server is valid from inside docker-compose/kubernetes)
SAN_DNS="kt-server"
CERTIP="35.184.134.53"

function usage()
{
    echo "Usage: ./$0 [-f]"
    echo "  -f force non-interactive mode"
    echo ""
}

# TODO(ismail): add all user-input as flags:
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

##################################
##### Collecting information #####
##################################
function collectUserInput()
{
  echo "Do you want to configure the frontend?"
  select yn in "Yes" "No"; do
      case "${yn}" in
    Yes) FRONTEND=1; break;;
    No) FRONTEND=0; break;;
      esac
  done

  echo "Do you want to configure the backend?"
  select yn in "Yes" "No"; do
      case "${yn}" in
    Yes) BACKEND=1; break;;
    No)  BACKEND=0; break;;
      esac
  done

  if ((FRONTEND == 0 && BACKEND == 0)); then
      echo "You should configure either the frontend, the backend, or both"
      exit 1
  fi

  if ((FRONTEND == 1 && BACKEND == 0)); then
      echo "Which frontend is this?"
      select yn in "First" "Second"; do
    case "${yn}" in
        First) FRONTENDNUM=1; break;;
        Second) FRONTENDNUM=2; break;;
    esac
      done
  fi

  # Read IP addresss.
  if ((FRONTEND ^ BACKEND == 1)); then
      read -p "Enter the first frontend's IP address: " IP1
      read -p "Enter the second frontend's IP address: " IP2
      read -p "Enter the backend's IP address: " IP3
  fi

  # Read service_key.json path.
  read -p "Path to application credentials file: " SERVICEKEY

  if ((FRONTEND == 1)); then
      # Read listen address.
      read -p "Listen IP address, e.g., localhost, (to listen on all IPs, use empty string): " LISTENADDR

      # Read certificate related information.
      read -p "Frontend domain name (optional): " CERTDOMAIN
      read -p "Frontend public IP address (optional): " CERTIP_TEMP
      if [[ -n "${CERTIP_TEMP}" ]]; then
        CERTIP="${CERTIP_TEMP}"
      fi
  fi
}

if ((INTERACTIVE == 1)); then
  collectUserInput
fi

#####################
##### Executing #####
#####################

cd "${GOPATH}/src/github.com/google/keytransparency"

# Create keys.
if ((FRONTEND == 1)); then
    ./scripts/gen_server_keys.sh -d "${CERTDOMAIN}" -a "${CERTIP}" -s "${SAN_DNS}"
fi

if ((MONITOR == 1)); then
    ./scripts/gen_monitor_keys.sh -f
fi
