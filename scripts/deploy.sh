#!/usr/bin/env bash

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

set -ex

function main()
{
  # create key-pairs:
  ./scripts/prepare_server.sh -f
  #prepareSecrets # TODO(gbelvin): Use secrets volume.
  docker-compose build
  docker-compose push

  # Deploy all trillian related services.
  kubectl apply -f deploy/kubernetes/.
}


function prepareSecrets()
{
  local EXISTS=0
  # if kt-secrets does not exist, create it:
  kubectl get secret kt-secrets
  # kubectl exits with 1 if kt-secret does not exist
  if [ $? -ne 0 ]; then
    kubectl create secret generic kt-secrets --from-file=genfiles/server.crt --from-file=genfiles/server.key 
  fi
}

# Run everything:
main
