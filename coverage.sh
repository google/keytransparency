#!/usr/bin/env bash

set -e
mkdir -p out
go list ./... | grep -v vendor | parallel -k go test -coverprofile=out/{#} {}
cat out/* > coverage.txt
