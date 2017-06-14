#!/usr/bin/env bash

# Following assumptions are made by this script:

PROJECT_NAME=transparent-keyserver

gcloud --quiet version
gcloud auth activate-service-account --key-file client-secret.json
gcloud --quiet components update kubectl
gcloud config set project ${PROJECT_NAME}
gcloud config set compute/zone us-central1-b

# Build using docker compose
#docker-compose build

# Work around some git permission issues on linux:
chmod a+r ../../trillian/storage/mysql/storage.sql
# Create and push a fresh db image (with schema created)
docker build -t  us.gcr.io/${PROJECT_NAME}/db -f ../kubernetes/mysql-trillian/Dockerfile ../..
gcloud docker -- push us.gcr.io/${PROJECT_NAME}/db

images=("trillian_log_server" "trillian_map_server" "keytransparency-server" \
"trillian_log_signer" "keytransparency-signer")
for DOCKER_IMAGE_NAME in "${images[@]}"
do
  docker tag ${DOCKER_IMAGE_NAME} us.gcr.io/${PROJECT_NAME}/${DOCKER_IMAGE_NAME}
  # Push the images as we refer to them in the kubernetes config files:
  gcloud docker -- push us.gcr.io/${PROJECT_NAME}/${DOCKER_IMAGE_NAME}
done

kubectl apply -f kubernetes/trillian-deployment.yml

# We need to be sure trillian-map is up and running before we create the tree:

# get the name of the pod we are looking for:
# kubectl get pods --selector=run=trillian-map -o jsonpath={.items[*].metadata.name}
# Ugly way to get a log-id:
# LOGID=$(echo 'go run $GOPATH/src/github.com/google/trillian/cmd/createtree/main.go --admin_server=localhost:8090 --pem_key_path=testdata/log-rpc-server.privkey.pem --pem_key_password="towel" --signature_algorithm=ECDSA --tree_type=LOG' | kubectl exec -it trillian-map-2888489038-lx634 -- /bin/sh )
# TODO: put log and map-id into config map? (https://kubernetes.io/docs/tasks/configure-pod-container/configmap/)

# TODO run this command on the trillian-map instead (will simplify things for Docker and other deployments, too):
# curl -X POST -d '{"tree":{"tree_state":1,"tree_type":1,"hash_algorithm":4,"hash_strategy":1,"signature_algorithm":3},"key_spec":{"ecdsa_params":{"curve":1}}}'  http://localhost:8091/v1beta/trees

# TODO(ismail): additionally to above container images we might want one that
# simply queries (the equivalent of) https://localhost:8080/v1/users/foo@bar.com
# later we would want one that runs a client, too
