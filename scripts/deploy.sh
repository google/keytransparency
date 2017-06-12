#!/usr/bin/env bash

PROJECT_NAME=transparent-keyserver
#TODO(ismail): build with docker-compose, then (re)tag and push
# build using docker compose
docker-compose build

#TODO(ismail): this needs to be manually synced with docker-compose.yml; find a
# better way
images=("trillian_log_server" "trillian_map_server" "keytransparency-server" \
"trillian_log_signer" "keytransparency-signer")
for DOCKER_IMAGE_NAME in "${images[@]}"
do
  echo ${DOCKER_IMAGE_NAME}
	docker tag ${DOCKER_IMAGE_NAME} us.gcr.io/${PROJECT_NAME}/${DOCKER_IMAGE_NAME}:$TRAVIS_COMMIT
	#TODO gcloud docker -- push us.gcr.io/${PROJECT_NAME}/${DOCKER_IMAGE_NAME}
done
