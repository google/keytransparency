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
export TRAVIS_COMMIT=$(git rev-parse HEAD)

gcloud --quiet config set project ${PROJECT_NAME_CI}
gcloud --quiet config set compute/zone ${CLOUDSDK_COMPUTE_ZONE}
gcloud --quiet config set container/cluster ${CLUSTER_NAME_CI}
gcloud --quiet container clusters get-credentials ${CLUSTER_NAME_CI}
gcloud --quiet auth configure-docker

# Test current directory before deleting anything
test $(basename $(pwd)) == "keytransparency" || exit 1

# kubectl exits with 1 if kt-secret does not exist
if ! kubectl get secret kt-tls; then
  echo "Generating keys..."
  rm -f ./genfiles/*
  ./scripts/prepare_server.sh -f
  kubectl create secret generic kt-monitor --from-file=genfiles/monitor_sign-key.pem
  kubectl create secret tls kt-tls --cert=genfiles/server.crt --key=genfiles/server.key
fi

echo "Building docker images..."
docker-compose build --parallel

echo "Pushing docker images..."
docker-compose push

echo "Updating jobs..."
cd deploy/kubernetes/base
kustomize edit set image gcr.io/${PROJECT_NAME_CI}/prometheus:${TRAVIS_COMMIT}
kustomize edit set image gcr.io/${PROJECT_NAME_CI}/keytransparency-monitor:${TRAVIS_COMMIT}
kustomize edit set image gcr.io/${PROJECT_NAME_CI}/keytransparency-sequencer:${TRAVIS_COMMIT}
kustomize edit set image gcr.io/${PROJECT_NAME_CI}/keytransparency-server:${TRAVIS_COMMIT}
cd -
kubectl apply -k deploy/kubernetes/overlays/gke
