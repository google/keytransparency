#!/bin/bash
openssl ecparam -name prime256v1 -genkey -noout -out p256-key.pem
openssl ec -in p256-key.pem -pubout -out p256-pubkey.pem



