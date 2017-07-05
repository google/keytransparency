#!/bin/bash
#
# Checks for lint errors, spelling, licensing and so on.
set -eu

check_deps() {
  local failed=0
  check_cmd golint github.com/golang/lint/golint || failed=10
  check_cmd errcheck github.com/kisielk/errcheck || failed=11
  check_cmd gocyclo github.com/fzipp/gocyclo || failed=12
  check_cmd ineffassign github.com/gordonklaus/ineffassign || failed=13
  check_cmd misspell github.com/client9/misspell/cmd/misspell || failed=14
  return $failed
}

check_cmd() {
  local cmd="$1"
  local repo="$2"
  if ! type -p "${cmd}" > /dev/null; then
    echo "${cmd} not found, try to 'go get -u ${repo}'"
    return 1
  fi
}

main() {
  check_deps

  local fail=0
  local go_srcs="$(find . -name '*.go' | \
    grep -v mock_ | \
    grep -v .pb.go | \
    grep -v .pb.gw.go | \
    grep -v _string.go | \
    grep -v vendor/ | \
    tr '\n' ' ')"
  local proto_srcs="$(find . -name '*.proto' | \
    grep -v vendor/ | \
    tr '\n' ' ')"

  printf "running gofmt...\n"
  find . -iregex '.*.go' ! -path "./vendor/*" -exec gofmt -s -w {} \;
  status=$(git status --porcelain)
  if [[ -n ${status} ]]; then
    printf "gofmt changed the following files:\n${status}\n"
    git status
    git diff
    fail=1
  fi

  printf "running golint...\n"
  status=$(find . -iregex '.[^.]*.go' ! -path "./vendor/*" -exec golint {} \;)
  if [[ -n ${status} ]]; then
    printf "golint found the following issues:\n${status}\n"
  fi

  printf "running go vet...\n"
  status=$(go vet ./cmd/... ./core/... ./impl/... ./integration/...)
  if [[ -n ${status} ]]; then
    printf "go vet found the following issues:\n${status}\n"
    fail=1
  fi

  printf "running errcheck...\n"
  status=$(find . ! -path "*/proto/*" ! -iwholename "*.git*" ! -iwholename "." ! -iwholename "*vendor*" -type d ! -name "proto" -exec errcheck -ignore 'Close|Write|Serve,os:Remove' {} \;)
  if [[ -n ${status} ]]; then
    printf "errcheck found the following issues:\n${status}\n"
    fail=1
  fi

  printf "running gocyclo...\n"
  status=$(find . -type f -name "*.go" ! -path "./vendor/*" ! -name "*.pb*go" -exec gocyclo -over 15 {} \;)
  if [[ -n ${status} ]]; then
    printf "gocyclo found the following issues:\n${status}\n"
    fail=1
  fi

  printf "running ineffassign...\n"
  status=$(ineffassign .)
  if [[ -n ${status} ]]; then
    printf "ineffassign found the following issues:\n${status}\n"
    fail=1
  fi

  printf "running misspell...\n"
  status=$(find . -type f -name '*.md' ! -path "./vendor/*" -o -name '*.go' ! -path "./vendor/*" -o -name '*.proto' ! -path "./vendor/*" | sort | xargs misspell -locale US)
  if [[ -n ${status} ]]; then
    printf "misspell found the following issues:\n${status}\n"
    fail=1
  fi

  printf "checking license header...\n"
  local nolicense="$(grep -L 'Apache License' ${go_srcs} ${proto_srcs})"
  if [[ "${nolicense}" ]]; then
    printf "Missing license header in:\n${nolicense}\n"
    fail=1
  fi

  exit $fail
}

main "$@"
