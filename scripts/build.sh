#!/usr/bin/env bash

set -e

SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ] ; do SOURCE="$(readlink "$SOURCE")"; done
cd -P "$( dirname "$SOURCE" )/.."

SUPPORTED_ARCHES=( "linux/amd64" "windows/amd64" )

for supported_arch in "${SUPPORTED_ARCHES[@]}"
do
    IFS="/" read -r -a os_arch_split <<< "$supported_arch"
    os="${os_arch_split[0]}"
    arch="${os_arch_split[1]}"
    binary_extension=""
    if [ "$os" == "windows" ]; then
        binary_extension=".exe"
    fi
    echo "Building ${supported_arch}…"
    GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 go build -trimpath \
        -ldflags="-X github.com/emmansun/vault-gmsm-plugin/version.GitCommit='$(git rev-parse HEAD)'" \
        -o "pkg/${os}_${arch}/vault-gmsm-plugin${binary_extension}"
done

while IFS= read -r -d '' platform
do
    osarch=$(basename "$platform")

    pushd "$platform" >/dev/null 2>&1
    sha256sum -- * > "$osarch".sha256sum
    zip ../"$osarch".zip ./*
    popd >/dev/null 2>&1
done <   <(find ./pkg -mindepth 1 -maxdepth 1 -type d -print0)