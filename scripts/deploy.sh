#!/usr/bin/env bash

PROJECT_NAME=transparent-keyserver

# Make sure we are in a travis build environment:
if [ ! "$TRAVIS" = "true" ] && [ ! "$CI" = "true" ]; then
  echo "$0 is only meant to run inside travis images/from travis.yml"
  exit 1
fi

# Only run deploy if we are on master and not a PR:
if [ "$TRAVIS_BRANCH" = "master" ] && [ "$TRAVIS_PULL_REQUEST" = "false" ]; then
  gcloud --quiet version
  gcloud auth activate-service-account --key-file client-secret.json
  gcloud --quiet components update kubectl
  gcloud config set project ${PROJECT_NAME}
  gcloud config set compute/zone us-central1-b

  # Build using docker compose
  docker-compose build

  #TODO(ismail): this needs to be manually synced with docker-compose.yml; find a
  # better way
  images=("trillian_log_server" "trillian_map_server" "keytransparency-server" \
  "trillian_log_signer" "keytransparency-signer")
  for DOCKER_IMAGE_NAME in "${images[@]}"
  do
    # Tag with current commit: If sth fails we can reproduce which merge
    # triggered the error:
    docker tag ${DOCKER_IMAGE_NAME} us.gcr.io/${PROJECT_NAME}/${DOCKER_IMAGE_NAME}:${TRAVIS_COMMIT}
    # Push the images as we refer to them in the kubernetes config files:
    gcloud docker -- push us.gcr.io/${PROJECT_NAME}/${DOCKER_IMAGE_NAME}:${TRAVIS_COMMIT}
  done

  # TODO(ismail): actually run the images and some integration tests
  # kubectl apply -f kubernetes/keytransparency-deployment.yml
  # TODO(ismail): additionally to above container images we might want one that
  # simply queries (the equivalent of) https://localhost:8080/v1/users/foo@bar.com
  # later we would want one that runs a client, too
fi