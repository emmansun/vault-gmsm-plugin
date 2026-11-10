#!/usr/bin/env bash

set -e

SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ] ; do SOURCE="$(readlink "$SOURCE")"; done
cd -P "$( dirname "$SOURCE" )/.."

SUPPORTED_ARCHES=( "linux/amd64" "windows/amd64" )

# Both plugins come out of this module. Each entry is <binary>:<package>, and
# the binary name is what Vault registers as the plugin name: Vault looks for a
# file named exactly after the registered name, so a long prefix here would be a
# long prefix in every register and enable command.
BINARIES=(
    "vault-gmsm-plugin:."
    "pki-gmsm:./cmd/pki-gmsm"
)

for supported_arch in "${SUPPORTED_ARCHES[@]}"
do
    IFS="/" read -r -a os_arch_split <<< "$supported_arch"
    os="${os_arch_split[0]}"
    arch="${os_arch_split[1]}"
    binary_extension=""
    if [ "$os" == "windows" ]; then
        binary_extension=".exe"
    fi
    for entry in "${BINARIES[@]}"
    do
        binary="${entry%%:*}"
        package="${entry#*:}"
        echo "Building ${binary} for ${supported_arch}…"
        GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 go build -trimpath \
            -ldflags="-X github.com/emmansun/vault-gmsm-plugin/version.GitCommit='$(git rev-parse HEAD)'" \
            -o "pkg/${os}_${arch}/${binary}${binary_extension}" "$package"
    done
done

while IFS= read -r -d '' platform
do
    osarch=$(basename "$platform")

    pushd "$platform" >/dev/null 2>&1
    sha256sum -- * > "$osarch".sha256sum
    zip ../"$osarch".zip ./*
    popd >/dev/null 2>&1
done <   <(find ./pkg -mindepth 1 -maxdepth 1 -type d -print0)