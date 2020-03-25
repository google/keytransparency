#!/usr/bin/env bash
set -ex

# This script sets the image tag used by kustomize.
# It takes an optional argument specifying the image tag.
# If the argument is omitted, the script will use the current git commit as the tag.
TRAVIS_COMMIT=${1:-$(git rev-parse HEAD)}
cd deploy/kubernetes/base
kustomize edit set image gcr.io/key-transparency/keytransparency-monitor:${TRAVIS_COMMIT}
kustomize edit set image gcr.io/key-transparency/keytransparency-sequencer:${TRAVIS_COMMIT}
kustomize edit set image gcr.io/key-transparency/keytransparency-server:${TRAVIS_COMMIT}
kustomize edit set image gcr.io/key-transparency/init:${TRAVIS_COMMIT}
cd -

