#!/usr/bin/env bash
#set -o pipefail
#set -o errexit
#set -o nounset
#set -o xtrace
set -eufx

################################################################################
# Following assumptions are made by this script:                               #
# * gcloud, docker, and docker-compose is installed                            #
# * it is called from $GOPATH/src/github.com/google/keytransparency            #
# * there is a project called key-transparency on gce  which has has gke       #
#   enabled and a cluster configured; gcloud is already set to this            #
#   project via:                                                               #
#   # see gcloud help auth and authenticate, then:                             #
#   gcloud config set project key-transparency                                 #
#   gcloud container clusters get-credentials <your-cluster-name>              #
#   gcloud config set compute/zone <your-compute-zone>                         #
#                                                                              #
#   See the project's .travis.yml file for a working example.                  #
#                                                                              #
################################################################################


export PROJECT_NAME_CI=key-transparency
export CLOUDSDK_COMPUTE_ZONE=us-central1-a
export CLUSTER_NAME_CI=ci-cluster


gcloud --quiet config set project ${PROJECT_NAME_CI}
gcloud --quiet config set compute/zone ${CLOUDSDK_COMPUTE_ZONE}
gcloud --quiet config set container/cluster ${CLUSTER_NAME_CI}
gcloud --quiet container clusters get-credentials ${CLUSTER_NAME_CI}
gcloud --quiet auth configure-docker


echo "Generating keys..."
rm -f ./genfiles/*
./scripts/prepare_server.sh -f
# kubectl exits with 1 if kt-secret does not exist
kubectl get secret kt-secrets
if [ $? -ne 0 ]; then
  kubectl create secret generic kt-secrets --from-file=genfiles/server.crt --from-file=genfiles/server.key
fi

echo "Building docker images..."
docker-compose build


echo "Pushing docker images..."
docker-compose push

echo "Tagging docker images..."
gcloud --quiet container images add-tag us.gcr.io/${PROJECT_NAME_CI}/prometheus:${TRAVIS_COMMIT} us.gcr.io/${PROJECT_NAME_CI}/prometheus:latest
gcloud --quiet container images add-tag us.gcr.io/${PROJECT_NAME_CI}/log-server:${TRAVIS_COMMIT} us.gcr.io/${PROJECT_NAME_CI}/log-server:latest
gcloud --quiet container images add-tag us.gcr.io/${PROJECT_NAME_CI}/log-signer:${TRAVIS_COMMIT} us.gcr.io/${PROJECT_NAME_CI}/log-signer:latest
gcloud --quiet container images add-tag us.gcr.io/${PROJECT_NAME_CI}/map-server:${TRAVIS_COMMIT} us.gcr.io/${PROJECT_NAME_CI}/map-server:latest
gcloud --quiet container images add-tag us.gcr.io/${PROJECT_NAME_CI}/keytransparency-server:${TRAVIS_COMMIT} us.gcr.io/${PROJECT_NAME_CI}/keytransparency-server:latest
gcloud --quiet container images add-tag us.gcr.io/${PROJECT_NAME_CI}/keytransparency-sequencer:${TRAVIS_COMMIT} us.gcr.io/${PROJECT_NAME_CI}/keytransparency-sequencer:latest
gcloud --quiet container images add-tag us.gcr.io/${PROJECT_NAME_CI}/keytransparency-monitor:${TRAVIS_COMMIT} us.gcr.io/${PROJECT_NAME_CI}/keytransparency-monitor:latest


echo "Updating jobs..."
kubectl apply -f deploy/kubernetes/.
kubectl set image deploy/prometheus prometheus=us.gcr.io/${PROJECT_NAME_CI}/prometheus:${TRAVIS_COMMIT}
kubectl set image deploy/log-server log-server=us.gcr.io/${PROJECT_NAME_CI}/log-server:${TRAVIS_COMMIT}
kubectl set image deploy/log-signer log-signer=us.gcr.io/${PROJECT_NAME_CI}/log-signer:${TRAVIS_COMMIT}
kubectl set image deploy/map-server map-server=us.gcr.io/${PROJECT_NAME_CI}/map-server:${TRAVIS_COMMIT}
kubectl set image deploy/server server=us.gcr.io/${PROJECT_NAME_CI}/keytransparency-server:${TRAVIS_COMMIT}
kubectl set image deploy/sequencer sequencer=us.gcr.io/${PROJECT_NAME_CI}/keytransparency-sequencer:${TRAVIS_COMMIT}
kubectl set image deploy/monitor monitor=us.gcr.io/${PROJECT_NAME_CI}/keytransparency-monitor:${TRAVIS_COMMIT}
