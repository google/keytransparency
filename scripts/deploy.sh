#!/usr/bin/env bash

PROJECT_NAME=transparent-keyserver
# build using docker compose
docker-compose build

#TODO(ismail): this needs to be manually synced with docker-compose.yml; find a
# better way
images=("trillian_log_server" "trillian_map_server" "keytransparency-server" \
"trillian_log_signer" "keytransparency-signer")
for DOCKER_IMAGE_NAME in "${images[@]}"
do
  # TODO(ismail): do we want to update the images every commit? Probably not!
  # TODO(ismail): figure out a good workflow, e.g. deploy images for PRs to master
  # then, run some integration tests (already in install and not in deploy).
  # If we are a commit on master: do the same as above but tag images differently.
	docker tag ${DOCKER_IMAGE_NAME} us.gcr.io/${PROJECT_NAME}/${DOCKER_IMAGE_NAME}:${TRAVIS_COMMIT}
	gcloud docker -- push us.gcr.io/${PROJECT_NAME}/${DOCKER_IMAGE_NAME}:${TRAVIS_COMMIT}
done

# TODO(ismail): actually run the images and some integration tests
# TODO(ismail): additionally to above container images we might want one that
# simply queries (the equivalent of) https://localhost:8080/v1/users/foo@bar.com
# later we would want one that runs a client, too