#!/usr/bin/env bash
set -ex
set -o pipefail

if [ ! -f genfiles/key.pem ]; then
	./scripts/gen_monitor_keys.sh -f
	cd genfiles
	go run "$(go env GOROOT)/src/crypto/tls/generate_cert.go" --host localhost,127.0.0.1,::
	cd -
fi

export TRAVIS_COMMIT=$(git rev-parse HEAD)
docker-compose build --parallel
# Assumes there is a docker swarm already configured.
# docker swarm init
docker stack deploy -c docker-compose.yml -c docker-compose.prod.yml kt
trap "docker stack rm kt" INT EXIT
./scripts/docker-stack-wait.sh -t 180 -n sequencer kt
docker run -t --network kt_attachable gcr.io/key-transparency/init:${TRAVIS_COMMIT} sequencer:8080 -- curl -k -X POST https://sequencer:8080/v1/directories -d'{"directory_id":"default","min_interval":"1s","max_interval":"60s"}'
./scripts/docker-stack-wait.sh -t 180 kt

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
