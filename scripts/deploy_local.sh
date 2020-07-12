#!/usr/bin/env bash
set -e
set -o pipefail

usage() {
  echo "$(basename $0) deploy | undeploy"
  echo "  deploy: deploys the KeyTransparency server locally"
  echo "  undeploy: undeploys the KeyTransparency server"
}

function deploy() {
	# Generate server's keys
	if [ ! -f genfiles/key.pem ]; then
		./scripts/gen_monitor_keys.sh -f
		cd genfiles
		go run "$(go env GOROOT)/src/crypto/tls/generate_cert.go" --host localhost,127.0.0.1,::
		cd -
	fi

	# Start a docker swarm if not part of it
	case "$(docker info --format '{{.Swarm.LocalNodeState}}')" in
	active)
		echo "Node is already in swarm cluster";;
	*)
		docker swarm init;;
	esac

	# Build the service's image
	export TRAVIS_COMMIT=$(git rev-parse HEAD)
	docker-compose build --parallel

	# Deploy the set of services
	docker stack deploy -c docker-compose.yml -c docker-compose.prod.yml kt
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
}

function undeploy() {
	# Remove the stack "kt"
	docker stack rm kt
}

# Start a docker swarm if not part of it
case "$1" in
deploy)
	deploy;;
undeploy)
	undeploy;;
*)
	usage;;
esac