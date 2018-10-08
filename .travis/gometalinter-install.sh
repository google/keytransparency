#!/bin/bash

set -euo pipefail

readonly version="$GOMETALINTER_VERSION"
readonly archive_url="https://github.com/alecthomas/gometalinter/releases/download/v$version/gometalinter-$version-linux-amd64.tar.gz"
readonly gometalinter_dir="${TRAVIS_HOME}/gometalinter"

if [[ -f "$gometalinter_dir/gometalinter-$version-linux-amd64/gometalinter" ]]; then
    echo "gometalinter is already installed, skipping..."
    exit 0
fi

pushd "$gometalinter_dir"
curl -fsSLO "$archive_url"
tar xvf "gometalinter-$version-linux-amd64.tar.gz"
rm "gometalinter-$version-linux-amd64.tar.gz"
popd
