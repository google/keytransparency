#!/usr/bin/env bash
set -ex
set -o pipefail

# kubectl exits with 1 if kt-secret does not exist
if ! kubectl get secret kt-secrets; then
  echo "Generating keys..."
  rm -f ./genfiles/*
  ./scripts/prepare_server.sh -f
  kubectl create secret generic kt-secrets --from-file=genfiles/server.crt --from-file=genfiles/server.key --from-file=genfiles/monitor_sign-key.pem
fi

# Hack to wait for the default service account's creation. https://github.com/kubernetes/kubernetes/issues/66689
n=0; until ((n >= 60)); do kubectl -n default get serviceaccount default -o name && break; n=$((n + 1)); sleep 1; done; ((n < 60))


kubectl apply -k deploy/kubernetes/overlays/local 
TIMEOUT=2m
timeout ${TIMEOUT} kubectl rollout status deployment/db
timeout ${TIMEOUT} kubectl rollout status deployment/log-server
timeout ${TIMEOUT} kubectl rollout status deployment/log-signer
timeout ${TIMEOUT} kubectl rollout status deployment/map-server
# timeout ${TIMEOUT} kubectl rollout status deployment/monitor
timeout ${TIMEOUT} kubectl rollout status deployment/sequencer
timeout ${TIMEOUT} kubectl rollout status deployment/server
trap "kubectl delete -k deploy/kubernetes/overlays/local" INT EXIT

wget -T 60 --spider --retry-connrefused --waitretry=1 http://localhost:8081/metrics
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
