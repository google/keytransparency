#!/usr/bin/env bash
set -ex
set -o pipefail

if [ ! -f genfiles/server.key ]; then
	./scripts/prepare_server.sh -f
fi

docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
trap "docker-compose down" INT EXIT

set +e
wget -T 60 --spider --retry-connrefused localhost:443
wget -T 60 --spider --retry-on-http-error=404 --no-check-certificate https://localhost/v1/directories/default
set -e

PASSWORD="foobar"
go run ./cmd/keytransparency-client authorized-keys create-keyset --password=${PASSWORD}
go run ./cmd/keytransparency-client post foo@bar.com \
	--insecure \
	--data='dGVzdA==' \
	--password=${PASSWORD} \
	--kt-url=0.0.0.0:443 \
	--verbose \
	--logtostderr
