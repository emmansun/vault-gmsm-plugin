# Vault GMSM Plugin

[![CI](https://github.com/emmansun/vault-gmsm-plugin/actions/workflows/ci.yml/badge.svg)](https://github.com/emmansun/vault-gmsm-plugin/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/emmansun/vault-gmsm-plugin.svg)](https://pkg.go.dev/github.com/emmansun/vault-gmsm-plugin)
[![Go version](https://img.shields.io/github/go-mod/go-version/emmansun/vault-gmsm-plugin)](go.mod)
[![Release](https://img.shields.io/github/v/release/emmansun/vault-gmsm-plugin?sort=semver)](https://github.com/emmansun/vault-gmsm-plugin/releases)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Two [HashiCorp Vault](https://www.vaultproject.io/) plugins for the ShangMi (SM,
国密) algorithms:

- **`vault-gmsm-plugin`** — a transit secrets engine for SM4-GCM encryption and
  SM2 signing. Keys are generated inside Vault, or imported from material you
  already hold, and never leave the mount unless the key is marked exportable.
  Request and response shapes follow the transit secrets engine of Vault 1.14,
  so existing transit tooling, policies and client libraries carry over with the
  mount path changed.
- **`pki-gmsm`** — a certificate authority for the same algorithms: it generates
  SM2 keys, signs X.509 certificates with `SM2WithSM3` and publishes a CRL. It
  is a mount type of its own, because Vault binds one plugin to one mount and
  because the lifecycle of a CA has nothing in common with that of a transit
  key.

## Capabilities

| Mount | Key type | Operations |
| --- | --- | --- |
| `gmsm` | `sm4-gcm96` (default) | Encrypt, decrypt, rewrap, data keys, key derivation, convergent encryption, associated data |
| `gmsm` | `sm2` | Encrypt, decrypt, rewrap, data keys, sign, verify, certificate requests |
| `gmsm` | `hmac` | HMAC-SM3 only, with a key size between 32 and 512 bytes |
| `pki` | `sm2` | Root and intermediate authorities, roles with a name policy, issue, sign, revoke, CRL, tidy |

HMAC-SM3 is available on every key version regardless of type, so an `sm2` key
can also produce and verify HMACs. The older type name `ecdsa-sm2` is still
accepted on every path that takes a type, and a key created with it reports
`sm2`. All three transit key types also accept imported key material.

Unsupported combinations are rejected rather than half-implemented: `sm4-cmac`
keys fail at creation, and encryption, decryption or signing with a key type
that does not support them is refused.

## Install

Put the release binary for your platform and architecture in Vault's plugin
directory, then register and enable it. The name passed to
`vault plugin register` has to match the file name, including the `.exe` suffix
on Windows:

```bash
vault plugin register -sha256="$(sha256sum /etc/vault/plugins/vault-gmsm-plugin | cut -d' ' -f1)" \
  secret vault-gmsm-plugin
vault secrets enable -path=gmsm vault-gmsm-plugin

vault plugin register -sha256="$(sha256sum /etc/vault/plugins/pki-gmsm | cut -d' ' -f1)" \
  secret pki-gmsm
vault secrets enable -path=pki-gmsm pki-gmsm
```

Building from source, checksum files, the Windows build script, the Vault and Go
versions supported, and the operational caveats are in
[Operations](docs/operations.md).

## Quick start

The walkthrough below runs against a Vault dev server:

```bash
# Vault 2.x probes every binary in -dev-plugin-dir at startup and aborts when a
# file is not a database plugin. Start with an empty directory and copy the
# binaries in once the server is up.
mkdir -p ./plugins
vault server -dev -dev-root-token-id=root -dev-plugin-dir=./plugins

# in a second shell; point the copy at wherever the binaries came from
export VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root
cp pkg/linux_amd64/vault-gmsm-plugin pkg/linux_amd64/pki-gmsm ./plugins/
for name in vault-gmsm-plugin pki-gmsm; do
  vault plugin register -sha256="$(sha256sum ./plugins/$name | cut -d' ' -f1)" secret "$name"
done
vault secrets enable -path=gmsm vault-gmsm-plugin
vault secrets enable -path=pki-gmsm pki-gmsm
```

Encrypt with SM4-GCM. The CLI base64-encodes nothing on its own, so the input to
`encrypt` has to be base64 already:

```console
$ vault write -f gmsm/keys/mykey
Success! Data written to: gmsm/keys/mykey

$ vault write gmsm/encrypt/mykey plaintext="$(printf 'my secret data' | base64)"
Key            Value
---            -----
ciphertext     vault:v1:9J0YlZbF8kQ0dCk8X1sYz1r6FjJ2mQ4lZ0dU6T7hE2c=
key_version    1

$ vault write gmsm/decrypt/mykey ciphertext=vault:v1:9J0YlZbF8kQ0dCk8X1sYz1r6FjJ2mQ4lZ0dU6T7hE2c=
Key         Value
---         -----
plaintext   bXkgc2VjcmV0IGRhdGE=
```

Ciphertexts are bound to the key version that produced them. `rotate` adds a
version, and `rewrap` moves an existing ciphertext to the latest one without
exposing the plaintext:

```console
$ vault write -f gmsm/keys/mykey/rotate
$ vault read -field=latest_version gmsm/keys/mykey
2

$ vault write -field=ciphertext gmsm/rewrap/mykey \
    ciphertext=vault:v1:9J0YlZbF8kQ0dCk8X1sYz1r6FjJ2mQ4lZ0dU6T7hE2c=
vault:v2:oQ7Xb2cR4mN0yY8sK1pL5vT3jH6gF9dA2sE4rU8iO0k=
```

Issue a certificate from the authority:

```console
$ vault write pki-gmsm/root/generate/internal common_name="Example Root CA" ttl=87600h
$ vault write pki-gmsm/roles/web allowed_domains=example.com allow_subdomains=true \
    ttl=24h max_ttl=720h
$ vault write pki-gmsm/issue/web common_name=web.example.com alt_names=api.example.com
```

## Documentation

| Document | Contents |
| --- | --- |
| [Transit engine](docs/transit.md) | Key types, the endpoint reference (keys, encrypt, sign, HMAC, export), certificate requests, key import, and how this mount differs from transit |
| [Certificate authority](docs/pki.md) | Generating the authority, roles and the name policy, issue and sign, revocation and the CRL, intermediates, and how this plugin differs from pki |
| [Operations](docs/operations.md) | Compatibility, installation in detail, operational notes, the source layout, development commands and the CI jobs |

## License

These plugins are distributed under the MIT license; see [LICENSE](LICENSE).

The shape of the transit plugin's request and response fields follows the transit
secrets engine of HashiCorp Vault, which was published under MPL-2.0 up to
release 1.14.0. The parts of `gmsm/` that originate from those releases are
therefore also available under the MPL-2.0. Releases 1.15.0 and later of that
repository are licensed under BUSL-1.1 and are deliberately not used as a source
here.
