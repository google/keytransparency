#!/usr/bin/env bash

# Copyright 2017, Yahoo Holdings Inc.
# Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

WD=run_docker

cd "${GOPATH}/src/github.com/yahoo/bftkv/scripts"
mkdir -p $WD
setup.sh -host bftkv $WD

# Create output directory.
mkdir -p "${GOPATH}/src/github.com/google/keytransparency/genfiles/bftkv.key"
cp -pf $WD/keys/u01/* "${GOPATH}/src/github.com/google/keytransparency/genfiles/bftkv.key/"
