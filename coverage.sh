#!/usr/bin/env bash

set -e
mkdir -p out
go list ./... | parallel -k go test -coverprofile=out/{#} {}
cat out/* > coverage.txt
