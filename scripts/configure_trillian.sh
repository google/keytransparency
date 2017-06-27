#!/usr/bin/env bash

# Defaults from docker-compose.yml.
LOG_URL=localhost:8091
MAP_URL=localhost:8094

function createLog()
{
  LOG_JSON=`curl -X POST -d  '{"tree":{"tree_state":"ACTIVE","tree_type":"LOG","hash_strategy":"RFC6962_SHA256","signature_algorithm":"ECDSA","max_root_duration":"0","hash_algorithm":"SHA256"},"key_spec":{"ecdsa_params":{"curve":"P256"}}}'  http://${LOG_URL}/v1beta1/trees`
  export LOG_ID=`echo ${LOG_JSON} | jq -r '.tree_id'`
  echo "-----BEGIN PUBLIC KEY-----" > genfiles/trillian-log.pem
  echo $LOG_JSON | jq '.public_key.der'  | sed 's/\"//g' | cat >> genfiles/trillian-log.pem
  echo "-----END PUBLIC KEY-----" >> genfiles/trillian-log.pem
}

function createMap()
{
  MAP_JSON=`curl -X POST -d  '{"tree":{"tree_state":"ACTIVE","tree_type":"MAP","hash_strategy":"TEST_MAP_HASHER","signature_algorithm":"ECDSA","max_root_duration":"0","hash_algorithm":"SHA256"},"key_spec":{"ecdsa_params":{"curve":"P256"}}}'  http://${MAP_URL}/v1beta1/trees`
  export MAP_ID=`echo ${MAP_JSON} | jq -r '.tree_id'`
  echo "-----BEGIN PUBLIC KEY-----" > genfiles/trillian-map.pem
  echo $MAP_JSON | jq -r '.public_key.der'  | cat >> genfiles/trillian-map.pem
  echo "-----END PUBLIC KEY-----" >> genfiles/trillian-map.pem
}