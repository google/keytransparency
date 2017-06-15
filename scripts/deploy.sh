#!/usr/bin/env bash

# Following assumptions are made by this script:

PROJECT_NAME=transparent-keyserver
NAME_SPACE=default

MAX_RETRY=30

function main()
{
  # create key-pairs:
  ./prepare_server.sh -f
  initGcloud
  buildDockerImgs
  tearDown
  pushTrillianImgs

  # Deploy all trillian related services:
  kubectl apply -f ../kubernetes/trillian-deployment.yml

  pushKTImgs
  waitForTrillian
  createTreeAndSetIDs

  # Deploy all keytransparency related services (server and signer):
  kubectl apply -f ../kubernetes/keytransparency-deployment.yml
}

function initGcloud()
{
  gcloud --quiet version
  gcloud auth activate-service-account --key-file client-secret.json
  # This might fail locally but is necessary on travis:
  gcloud --quiet components update kubectl
  gcloud config set project ${PROJECT_NAME}
  gcloud config set compute/zone us-central1-b
}

function buildDockerImgs()
{
  # Build all images defined in the docker-compose.yml:
  (cd ../ && docker-compose build)
  # Separately build the DB:
  # Work around some git permission issues on linux:
  chmod a+r ../../trillian/storage/mysql/storage.sql
  # Create and push a fresh db image (with schema created)
  docker build -t  us.gcr.io/${PROJECT_NAME}/db -f ../kubernetes/mysql-trillian/Dockerfile ../..
}

function pushTrillianImgs()
{
  gcloud docker -- push us.gcr.io/${PROJECT_NAME}/db
  images=("trillian_log_server" "trillian_map_server" "keytransparency-server" \
  "trillian_log_signer" "keytransparency-signer")
  for DOCKER_IMAGE_NAME in "${images[@]}"
  do
    docker tag ${DOCKER_IMAGE_NAME} us.gcr.io/${PROJECT_NAME}/${DOCKER_IMAGE_NAME}
    # Push the images as we refer to them in the kubernetes config files:
    gcloud docker -- push us.gcr.io/${PROJECT_NAME}/${DOCKER_IMAGE_NAME}
  done
}

function pushKTImgs()
{
 gcloud docker -- push us.gcr.io/${PROJECT_NAME}/db
  images=("keytransparency-server" "keytransparency-signer")
  for DOCKER_IMAGE_NAME in "${images[@]}"
  do
    docker tag ${DOCKER_IMAGE_NAME} us.gcr.io/${PROJECT_NAME}/${DOCKER_IMAGE_NAME}
    # Push the images as we refer to them in the kubernetes config files:
    gcloud docker -- push us.gcr.io/${PROJECT_NAME}/${DOCKER_IMAGE_NAME}
  done
}

function waitForTrillian()
{
  # Wait for trillian-map pod to be up:
  COUNTER=0
  MAPSRV=""
  until [ -n "$MAPSRV" ] || [  $COUNTER -gt $MAX_RETRY ]; do
    # Service wasn't up yet:
    sleep 10;
    let COUNTER+=1
    MAPSRV=$(kubectl get pods --selector=run=trillian-map -o jsonpath={.items[*].metadata.name});
  done

  if [ -n "$MAPSRV" ]; then
    echo "trillian-map service is up"
  else
    echo "Stopped waiting for trillian-map service. Quitting ..."
    exit 1;
  fi
}

function createTreeAndSetIDs()
{
  LOG_ID=""
  MAP_ID=""
  COUNTER=0
  until [ -n "$LOG_ID" ] || [  $COUNTER -gt $MAX_RETRY ]; do
    # RPC was not available yet, wait and retry:
    sleep 10;
    let COUNTER+=1
    LOG_ID=$(echo 'go run $GOPATH/src/github.com/google/trillian/cmd/createtree/main.go --admin_server=localhost:8090 --pem_key_path=testdata/log-rpc-server.privkey.pem --pem_key_password="towel" --signature_algorithm=ECDSA --tree_type=LOG' | kubectl exec -i $MAPSRV -- /bin/sh )
    MAP_ID=$(echo 'go run $GOPATH/src/github.com/google/trillian/cmd/createtree/main.go --admin_server=localhost:8090 --pem_key_path=testdata/log-rpc-server.privkey.pem --pem_key_password="towel" --signature_algorithm=ECDSA --tree_type=MAP' | kubectl exec -i $MAPSRV -- /bin/sh )
  done

  if [ -n "$LOG_ID" ] && [ -n "$MAP_ID" ]; then
    echo "Trees created with MAP_ID=$MAP_ID and LOG_ID=$LOG_ID"
    # Substitute LOG_ID and MAP_ID in template kubernetes file:
    export LOG_ID
    export MAP_ID
    envsubst < ../kubernetes/keytransparency-deployment.yml.tmpl > ../kubernetes/keytransparency-deployment.yml
  else
    echo "Failed to create tree. Need map-id and log-id before running kt-server/-signer."
    exit 1
  fi
}

function tearDown()
{
  kubectl delete --all services --namespace=$NAME_SPACE
  kubectl delete --all deployments --namespace=$NAME_SPACE
  kubectl delete --all pods --namespace=$NAME_SPACE
}

# Run everything:
main
