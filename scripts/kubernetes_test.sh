#!/usr/bin/env bash
set -ex
set -o pipefail

# This script assumes the existance of a local cluster
# go get sigs.k8s.io/kind@v0.6.1 
# kind create cluster --config deploy/kubernetes/kind-config.yaml
# kubectl cluster-info --context kind-kind

# Build docker images and make them available inside of the k8 cluster
export TRAVIS_COMMIT=$(git rev-parse HEAD)
docker-compose build --parallel
kind load docker-image gcr.io/key-transparency/keytransparency-monitor:${TRAVIS_COMMIT}
kind load docker-image gcr.io/key-transparency/keytransparency-sequencer:${TRAVIS_COMMIT}
kind load docker-image gcr.io/key-transparency/keytransparency-server:${TRAVIS_COMMIT}
kind load docker-image gcr.io/key-transparency/init:${TRAVIS_COMMIT}

./scripts/kustomize_image_tag.sh $TRAVIS_COMMIT

# kubectl exits with 1 if kt-secret does not exist
if ! kubectl get secret kt-tls; then
  echo "Generating keys..."
  rm -f ./genfiles/*
  ./scripts/gen_monitor_keys.sh -f
  kubectl create secret generic kt-monitor --from-file=genfiles/monitor_sign-key.pem
  go run "$(go env GOROOT)/src/crypto/tls/generate_cert.go" --host localhost,127.0.0.1,::
  kubectl create secret tls kt-tls --cert=cert.pem --key=key.pem
  rm key.pem cert.pem
fi

# Hack to wait for the default service account's creation. https://github.com/kubernetes/kubernetes/issues/66689
n=0; until ((n >= 60)); do kubectl -n default get serviceaccount default -o name && break; n=$((n + 1)); sleep 1; done; ((n < 60))

kustomize build deploy/kubernetes/overlays/local/ | kubectl apply -f -
trap "kustomize build deploy/kubernetes/overlays/local/ | kubectl delete -f -" INT EXIT
TIMEOUT=2m
timeout ${TIMEOUT} kubectl rollout status deployment/db
timeout ${TIMEOUT} kubectl rollout status deployment/log-server
timeout ${TIMEOUT} kubectl rollout status deployment/log-signer
timeout ${TIMEOUT} kubectl rollout status deployment/map-server
timeout ${TIMEOUT} kubectl rollout status deployment/monitor
timeout ${TIMEOUT} kubectl rollout status deployment/sequencer
timeout ${TIMEOUT} kubectl rollout status deployment/server

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
