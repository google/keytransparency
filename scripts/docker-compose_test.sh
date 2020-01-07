#!/usr/bin/env bash
set -ex
set -o pipefail

if [ ! -f genfiles/server.key ]; then
	./scripts/prepare_server.sh -f
fi

export TRAVIS_COMMIT=${TRAVIS_COMMIT:-$(git rev-parse HEAD)}
docker-compose build --parallel
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
trap "docker-compose down" INT EXIT
TIMEOUT=2m
timeout ${TIMEOUT} bash -c -- 'until [ "`docker inspect -f {{.State.Status}} $(docker-compose ps -q db)`" == "running" ]; do sleep 0.1; done;'
timeout ${TIMEOUT} bash -c -- 'until [ "`docker inspect -f {{.State.Status}} $(docker-compose ps -q log-server)`" == "running" ]; do sleep 0.1; done;'
timeout ${TIMEOUT} bash -c -- 'until [ "`docker inspect -f {{.State.Status}} $(docker-compose ps -q log-signer)`" == "running" ]; do sleep 0.1; done;'
timeout ${TIMEOUT} bash -c -- 'until [ "`docker inspect -f {{.State.Status}} $(docker-compose ps -q map-server)`" == "running" ]; do sleep 0.1; done;'
timeout ${TIMEOUT} bash -c -- 'until [ "`docker inspect -f {{.State.Status}} $(docker-compose ps -q sequencer)`" == "running" ]; do sleep 0.1; done;'
timeout ${TIMEOUT} bash -c -- 'until [ "`docker inspect -f {{.State.Status}} $(docker-compose ps -q server)`" == "running" ]; do sleep 0.1; done;'
timeout ${TIMEOUT} bash -c -- 'until [ "`docker inspect -f {{.State.Status}} $(docker-compose ps -q monitor)`" == "running" ]; do sleep 0.1; done;'

wget -T 60 --spider --retry-connrefused --waitretry=1 http://localhost:8081/readyz
wget -T 60 -O /dev/null --no-check-certificate  \
	--retry-connrefused --waitretry=1 \
	--retry-on-http-error=405,404,503 \
	https://localhost/v1/directories/default

PASSWORD="foobar"
go run ./cmd/keytransparency-client authorized-keys create-keyset --password=${PASSWORD}
go run ./cmd/keytransparency-client post foo@bar.com \
	--insecure \
	--data='dGVzdA==' \
	--password=${PASSWORD} \
	--kt-url=localhost:443 \
	--verbose \
	--timeout=2m \
	--logtostderr
