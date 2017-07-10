#!/usr/bin/env bash

# Defaults from docker-compose.yml.
LOG_URL=localhost:8091
MAP_URL=localhost:8094
LOCAL=true

function createLog()
{
  if [ "$LOCAL" = true ]; then
    CURL_OUT=`curl -o - -w "\n%{http_code}" -X POST http://${LOG_URL}/v1beta1/trees -d @scripts/log_payload.json`
  else
    # Run curl from inside the cluster
    LOGSRV=$(kubectl get pods --selector=run=trillian-log -o jsonpath={.items[*].metadata.name});
    CURL_OUT=`cat scripts/log_payload.json | kubectl exec -i ${LOGSRV} -- curl -o - -w "\n%{http_code}" -X POST http://trillian-log:8091/v1beta1/trees -d @-`
  fi
  HTTP_STATUS=`echo "${CURL_OUT}" | tail -n 1`
  if [ $HTTP_STATUS -ne "200" ]; then
    echo "curl failed with http_code=${HTTP_STATUS}"
    return -1
  fi
  LOG_JSON=`echo "${CURL_OUT}" | head -n 1`
  export LOG_ID=`echo ${LOG_JSON} | jq -r '.tree_id'`
  echo "-----BEGIN PUBLIC KEY-----" > genfiles/trillian-log.pem
  echo ${LOG_JSON} | head -n 1 | jq -r '.public_key.der' | cat >> genfiles/trillian-log.pem
  echo "-----END PUBLIC KEY-----" >> genfiles/trillian-log.pem
}

function createMap()
{
  if [ "$LOCAL" = true ]; then
    CURL_OUT=`curl -o - -w "\n%{http_code}" -X POST http://${MAP_URL}/v1beta1/trees -d @scripts/map_payload.json`
  else
  # Run curl from inside the cluster
    MAPSRV=$(kubectl get pods --selector=run=trillian-map -o jsonpath={.items[*].metadata.name});
    CURL_OUT=`cat scripts/map_payload.json | kubectl exec -i ${MAPSRV} -- curl -o - -w "\n%{http_code}" -X POST http://trillian-map:8091/v1beta1/trees -d @-`
  fi
  HTTP_STATUS=`echo "${CURL_OUT}" | tail -n 1`
  if [ $HTTP_STATUS -ne "200" ]; then
    echo "curl failed with http_code=${HTTP_STATUS}"
    return -1
  fi
  MAP_JSON=`echo "${CURL_OUT}" | head -n 1`
  export MAP_ID=`echo ${MAP_JSON} | jq -r '.tree_id'`
  echo "-----BEGIN PUBLIC KEY-----" > genfiles/trillian-map.pem
  echo ${MAP_JSON} | jq -r '.public_key.der' | cat >> genfiles/trillian-map.pem
  echo "-----END PUBLIC KEY-----" >> genfiles/trillian-map.pem
}