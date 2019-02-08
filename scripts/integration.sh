#!/usr/bin/env bash
set -ex
set -o pipefail

if [ ! -f genfiles/server.key ]; then
	./scripts/prepare_server.sh -f
fi

docker-compose up -d
trap "docker-compose down" INT EXIT

set +e
wget -q --spider --retry-connrefused --waitretry=1 -t 10 0.0.0.0:443 || sleep 2
wget -q --spider --retry-on-http-error=404 -t 30 1 0.0.0.0:443/v1/directories/default 
set -e

PASSWORD="foobar"
go run ./cmd/keytransparency-client/main.go authorized-keys create-keyset --password=${PASSWORD}
go run ./cmd/keytransparency-client/main.go post foo@bar.com \
	--insecure \
	--data='dGVzdA==' \
	--password=${PASSWORD} \
	--kt-url=0.0.0.0:443 \
	--verbose \
	--logtostderr
