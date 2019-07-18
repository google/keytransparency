#!/usr/bin/env bash
set -ex
set -o pipefail

if [ ! -f genfiles/server.key ]; then
	./scripts/prepare_server.sh -f
fi

docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
trap "docker-compose down" INT EXIT

set +e
wget -t 60 --spider --retry-connrefused --waitretry=1  0.0.0.0:443 || sleep 2
wget -t 60 --spider --retry-on-http-error=404  1 0.0.0.0:443/v1/directories/default
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
