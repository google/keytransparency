#!/usr/bin/env bash

# Defaults from docker-compose.yml.
LOG_URL=localhost:8091
MAP_URL=localhost:8094
KT_URL=localhost:8080

LOCAL=true

function retrieveTrees()
{
  if [ "$LOCAL" = true ]; then
    JSON=`curl -f http://${KT_URL}/v1/domain/info`
  else
    KTSRV=$(kubectl get pods --selector=run=kt-server -o jsonpath={.items[*].metadata.name})
    JSON=`kubectl exec -i ${KTSRV} -- curl http://kt-server:8080/v1/domain/info`
  fi

  export LOG_ID=`echo ${JSON} | jq -r '.log.tree_id'`
  echo "-----BEGIN PUBLIC KEY-----" > genfiles/trillian-log.pem
  echo ${JSON} | jq -r '.log.public_key.der' | cat >> genfiles/trillian-log.pem
  echo "-----END PUBLIC KEY-----" >> genfiles/trillian-log.pem

  export MAP_ID=`echo ${JSON} | jq -r '.map.tree_id'`
  echo "-----BEGIN PUBLIC KEY-----" > genfiles/trillian-map.pem
  echo ${JSON} | jq -r '.map.public_key.der' | cat >> genfiles/trillian-map.pem
  echo "-----END PUBLIC KEY-----" >> genfiles/trillian-map.pem
}

function createLog()
{
  if [ "$LOCAL" = true ]; then
    LOG_JSON=`curl -f -X POST http://${LOG_URL}/v1beta1/trees -d @scripts/log_payload.json`
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
    MAP_JSON=`curl -f -X POST http://${MAP_URL}/v1beta1/trees -d @scripts/map_payload.json`
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