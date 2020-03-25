#!/usr/bin/env bash

export PROJECT_NAME_CI=key-transparency
export CLOUDSDK_COMPUTE_ZONE=us-central1-a
export CLUSTER_NAME_CI=ci-cluster

gnudate() {
    if hash gdate 2>/dev/null; then
        gdate "$@"
    else
        date "$@"
    fi
}

echo "Cleaning old docker images..."
BEFORE_DATE=$(gnudate --date="30 days ago" +%Y-%m-%d)
./scripts/gcrgc.sh gcr.io/key-transparency/init $BEFORE_DATE
./scripts/gcrgc.sh gcr.io/key-transparency/prometheus $BEFORE_DATE
./scripts/gcrgc.sh gcr.io/key-transparency/keytransparency-server $BEFORE_DATE
./scripts/gcrgc.sh gcr.io/key-transparency/keytransparency-sequencer $BEFORE_DATE
./scripts/gcrgc.sh gcr.io/key-transparency/keytransparency-monitor $BEFORE_DATE
