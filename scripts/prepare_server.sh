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
declare -i DBENGINE

# Initialize variables.
FRONTEND=0
FRONTENDNUM=0
BACKEND=0
DBENGINE=1
DSN=""
IP1="127.0.0.1"
IP2="127.0.0.1"
IP3="127.0.0.1"
# 1 means SQLite, 2 means MySQL
SERVICEKEY=""
LISTENADDR=""
CERTDOMAIN=""
CERTIP=""


##################################
##### Collecting information #####
##################################

echo "Do you want to configure the frontend?"
select yn in "Yes" "No"; do
    case "${yn}" in
	Yes) FRONTEND=1; break;;
	No) break;;
    esac
done

echo "Do you want to configure the backend?"
select yn in "Yes" "No"; do
    case "${yn}" in
	Yes) BACKEND=1; break;;
	No) break;;
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

# Read the database engine.
echo "Database engine: SQLite or MySQL?"
select yn in "SQLite" "MySQL"; do
    case "${yn}" in
        SQLite) break;;
	MySQL) DBENGINE=2; break;;
    esac
done

# Read MySQL connection string if neccesary.
if ((DBENGINE == 2)); then
    read -p "MySQL DSN (more info https://github.com/go-sql-driver/mysql): " DSN
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
    read -p "Frontend public IP address (optional): " CERTIP
fi


#####################
##### Executing #####
#####################

cd "${GOPATH}/src/github.com/google/keytransparency"

# Building binaries.
if ((DBENGINE == 1)); then
    go build ./cmd/keytransparency-server
    go build ./cmd/keytransparency-signer
else
    go build -tags mysql ./cmd/keytransparency-server
    go build -tags mysql ./cmd/keytransparency-signer
fi

# Create keys.
if ((FRONTEND == 1)); then
    ./scripts/gen_server_keys.sh -d "${CERTDOMAIN}" -a "${CERTIP}"
fi

if ((BACKEND == 1)); then
    ./scripts/gen_signer_keys.sh
fi

# Generating .env file
ENV="PEER1=http://${IP1}:12380
PEER2=http://${IP2}:22380
PEER3=http://${IP3}:32380
LISTEN1=http://${IP1}:12379
LISTEN2=http://${IP2}:22379
LISTEN3=http://${IP3}:32379
LISTEN=\"http://${IP1}:12379,http://${IP2}:22379,http://${IP3}:32379\"
ETCD_INITIAL_CLUSTER=\"infra1=http://${IP1}:12380,infra2=http://${IP2}:22380,infra3=http://${IP3}:32380\"
ETCD_INITIAL_CLUSTER_STATE=new
ETCD_INITIAL_CLUSTER_TOKEN=etcd-cluster-1
ETCD_LOG_PACKAGE_LEVELS=\"*=WARNING\"
CTLOG=\"http://107.178.246.112\"
SIGN_PERIOD=5
GOOGLE_APPLICATION_CREDENTIALS=\"${SERVICEKEY}\""

if [[ -n "${CERTDOMAIN}" ]]; then
    ENV="${ENV}
DOMAIN=\"${CERTDOMAIN}\""
else
    ENV="${ENV}
DOMAIN=\"example.com\""
fi

if ((DBENGINE == 1)); then
    ENV="${ENV}
DB=\"genfiles/keytransparency-db.sqlite3\""
else
    ENV="${ENV}
DB=\"${DSN}\""
fi

if ((FRONTEND == 1)); then
    ENV="${ENV}
LISTEN_IP=\"${LISTENADDR}\"  # To listen on all IPs, use empty string.
KEY=\"genfiles/server.key\"
CERT=\"genfiles/server.crt\"
VRF_PRIV=\"genfiles/vrf-key.pem\"
VRF_PUB=\"genfiles/vrf-pubkey.pem\""
fi

if ((BACKEND == 1)); then
    ENV="${ENV}
SIGN_KEY=\"genfiles/p256-key.pem\""
fi

printf "%s\n" "${ENV}" > .env

# Generating Procfile.
PROCFILE="# Copyright 2016 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the \"License\");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an \"AS IS\" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"

if ((FRONTEND == 1 && BACKEND == 0)); then
       PROCFILE="${PROCFILE}
etcd: etcd --name infra${FRONTENDNUM} --listen-client-urls \$LISTEN${FRONTENDNUM} --advertise-client-urls \$LISTEN${FRONTENDNUM} --listen-peer-urls \$PEER${FRONTENDNUM} --initial-advertise-peer-urls \$PEER${FRONTENDNUM} --enable-pprof"
elif ((FRONTEND == 0 && BACKEND == 1)); then
       PROCFILE="${PROCFILE}
etcd: etcd --name infra3 --listen-client-urls \$LISTEN3 --advertise-client-urls \$LISTEN3 --listen-peer-urls \$PEER3 --initial-advertise-peer-urls \$PEER3 --enable-pprof"
elif ((FRONTEND == 1 && BACKEND == 1)); then
    PROCFILE="${PROCFILE}
etcd1: etcd --name infra1 --listen-client-urls \$LISTEN1 --advertise-client-urls \$LISTEN1 --listen-peer-urls \$PEER1 --initial-advertise-peer-urls \$PEER1 --enable-pprof
etcd2: etcd --name infra2 --listen-client-urls \$LISTEN2 --advertise-client-urls \$LISTEN2 --listen-peer-urls \$PEER2 --initial-advertise-peer-urls \$PEER2 --enable-pprof
etcd3: etcd --name infra3 --listen-client-urls \$LISTEN3 --advertise-client-urls \$LISTEN3 --listen-peer-urls \$PEER3 --initial-advertise-peer-urls \$PEER3 --enable-pprof"
fi

if ((FRONTEND == 1)); then
    PROCFILE="${PROCFILE}
frontend: ./keytransparency-server --addr=\$LISTEN_IP:\$PORT --key=\$KEY --cert=\$CERT --domain=\$DOMAIN --db=\$DB --maplog=\$CTLOG --etcd=\$LISTEN --vrf=\$VRF_PRIV"
fi

if ((BACKEND == 1)); then
    PROCFILE="${PROCFILE}
backend: ./keytransparency-signer --domain=\$DOMAIN --db=\$DB --maplog=\$CTLOG --etcd=\$LISTEN --period=\$SIGN_PERIOD --key=\$SIGN_KEY"
fi

printf "%s\n" "${PROCFILE}" > Procfile
