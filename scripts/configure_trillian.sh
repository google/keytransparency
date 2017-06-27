#!/usr/bin/env bash

# Defaults from docker-compose.yml.
LOG_URL=localhost:8091
MAP_URL=localhost:8094
LOCAL=true

function createLog()
{
  if [ "$LOCAL" = true ]; then
    LOG_JSON=`curl -X POST http://${LOG_URL}/v1beta1/trees -d @scripts/log_payload.json`
  else
    # Run curl from inside the cluster
    LOGSRV=$(kubectl get pods --selector=run=trillian-log -o jsonpath={.items[*].metadata.name});
    LOG_JSON=`cat scripts/log_payload.json | kubectl exec -i ${LOGSRV} -- curl -X POST http://trillian-log:8091/v1beta1/trees -d @-`
  fi

  export LOG_ID=`echo ${LOG_JSON} | jq -r '.tree_id'`
  echo "-----BEGIN PUBLIC KEY-----" > genfiles/trillian-log.pem
  echo ${LOG_JSON} | jq -r '.public_key.der' | cat >> genfiles/trillian-log.pem
  echo "-----END PUBLIC KEY-----" >> genfiles/trillian-log.pem
}

function createMap()
{
  if [ "$LOCAL" = true ]; then
    MAP_JSON=`curl -X POST http://${MAP_URL}/v1beta1/trees -d @scripts/map_payload.json`
  else
  # Run curl from inside the cluster
    MAPSRV=$(kubectl get pods --selector=run=trillian-map -o jsonpath={.items[*].metadata.name});
    MAP_JSON=`cat scripts/map_payload.json | kubectl exec -i ${MAPSRV} -- curl -X POST http://trillian-map:8091/v1beta1/trees -d @-`
  fi
  export MAP_ID=`echo ${MAP_JSON} | jq -r '.tree_id'`
  echo "-----BEGIN PUBLIC KEY-----" > genfiles/trillian-map.pem
  echo ${MAP_JSON} | jq -r '.public_key.der' | cat >> genfiles/trillian-map.pem
  echo "-----END PUBLIC KEY-----" >> genfiles/trillian-map.pem
}