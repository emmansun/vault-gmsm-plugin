# Vault GMSM Plugin

[![CI](https://github.com/emmansun/vault-gmsm-plugin/actions/workflows/ci.yml/badge.svg)](https://github.com/emmansun/vault-gmsm-plugin/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/emmansun/vault-gmsm-plugin.svg)](https://pkg.go.dev/github.com/emmansun/vault-gmsm-plugin)
[![Go version](https://img.shields.io/github/go-mod/go-version/emmansun/vault-gmsm-plugin)](go.mod)
[![Release](https://img.shields.io/github/v/release/emmansun/vault-gmsm-plugin?sort=semver)](https://github.com/emmansun/vault-gmsm-plugin/releases)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A [HashiCorp Vault](https://www.vaultproject.io/) secrets engine for the ShangMi
(SM, 国密) algorithms: SM4-GCM encryption and SM2 signing. Keys are generated
inside Vault and never leave the mount unless the key is marked exportable.

The request and response shapes follow the transit secrets engine of Vault 1.14,
so existing transit tooling, policies and client libraries carry over with the
mount path changed.

## Contents

- [Vault GMSM Plugin](#vault-gmsm-plugin)
  - [Contents](#contents)
  - [Capabilities](#capabilities)
  - [Compatibility](#compatibility)
  - [Installation](#installation)
    - [From a release](#from-a-release)
    - [From source](#from-source)
  - [Quick start](#quick-start)
  - [Key types](#key-types)
    - [`sm4-gcm96`](#sm4-gcm96)
    - [`ecdsa-sm2`](#ecdsa-sm2)
  - [Endpoint reference](#endpoint-reference)
    - [Creating keys](#creating-keys)
    - [Key configuration](#key-configuration)
    - [Encryption](#encryption)
    - [Data keys](#data-keys)
    - [Signing and verification](#signing-and-verification)
    - [Hashing and HMAC](#hashing-and-hmac)
    - [Export](#export)
  - [Certificates](#certificates)
  - [Differences from Vault transit](#differences-from-vault-transit)
  - [Operational notes](#operational-notes)
  - [Development](#development)
  - [License](#license)

## Capabilities

| Key type | Operations |
| --- | --- |
| `sm4-gcm96` (default) | Encrypt, decrypt, rewrap, data keys, key derivation, convergent encryption, associated data |
| `ecdsa-sm2` | Encrypt, decrypt, rewrap, data keys, sign, verify, certificate requests |
| `hmac` | HMAC-SM3 only, with a key size between 32 and 512 bytes |

HMAC-SM3 is available on every key version regardless of type, so an
`ecdsa-sm2` key can also produce and verify HMACs.

The following are deliberately rejected rather than half-implemented:

- `sm4-cmac` keys — creation fails with `sm4-cmac keys are not supported by this plugin`.
- Encryption, decryption and signing with a key type that does not support them.

## Compatibility

| | |
| --- | --- |
| Vault | 2.1.1 (exercised in CI), 1.17.3 (exercised manually) |
| Go | 1.26 or later, for building from source |
| Plugin protocol | Multiplexed gRPC plugin; the registered name has to match the binary file name |

The plugin is built against the Vault 2.1.1 module set. It is a standard
`logical.TypeLogical` backend, so it can be mounted and unmounted like any other
secrets engine.

## Installation

### From a release

Each release publishes a binary per platform together with a `sha256sum`. Copy
the binary for your platform and architecture into the plugin directory, then
register and enable it:

```bash
PLUGIN_DIR=/etc/vault/plugins
PLUGIN_NAME=vault-gmsm-plugin          # vault-gmsm-plugin.exe on Windows
CHECKSUM=$(sha256sum "$PLUGIN_DIR/$PLUGIN_NAME" | cut -d' ' -f1)

vault plugin register -sha256="$CHECKSUM" secret "$PLUGIN_NAME"
vault secrets enable -path=gmsm "$PLUGIN_NAME"
```

The name passed to `vault plugin register` has to match the file name in the
plugin directory, including the `.exe` suffix on Windows.

### From source

```bash
./scripts/build.sh          # linux/amd64 and windows/amd64 into pkg/<os>_<arch>/
```

Each output directory is accompanied by a `.sha256sum` file, which is what the
`-sha256` flag above expects. On Windows, `scripts\build.bat` builds a single
`plugin\vault-gmsm-plugin.exe` and writes `plugin\plugin.sha256sum` next to it.

## Quick start

The walkthrough below runs against a Vault dev server:

```bash
# Vault 2.x probes every binary in -dev-plugin-dir at startup and aborts when a
# file is not a database plugin. Start with an empty directory and copy the
# binary in once the server is up.
mkdir -p ./plugins
vault server -dev -dev-root-token-id=root -dev-plugin-dir=./plugins

# in a second shell; point the copy at wherever the binary came from
export VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root
cp pkg/linux_amd64/vault-gmsm-plugin ./plugins/
vault plugin register -sha256="$(sha256sum ./plugins/vault-gmsm-plugin | cut -d' ' -f1)" \
  secret vault-gmsm-plugin
vault secrets enable -path=gmsm vault-gmsm-plugin
```

Create a key and use it. The CLI base64-encodes nothing on its own, so the input
to `encrypt` has to be base64 already:

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

## Key types

### `sm4-gcm96`

SM4 in GCM mode with a 128-bit key and a 96-bit nonce. The nonce is generated per
request unless the caller supplies one.

| Feature | Notes |
| --- | --- |
| Key derivation | `derived=true` at creation; every request then carries a `context` that is mixed into the per-transaction key |
| Convergent encryption | Requires `derived=true`; requests must supply both `context` and a 96-bit `nonce`, and identical pairs produce identical ciphertexts |
| Associated data | `associated_data` is authenticated but not encrypted, and is not stored with the ciphertext, so it has to be supplied again on decrypt |
| Key size | Fixed at 128 bits |

`convergent_encryption=true` without `derived=true` is rejected at creation, and
so is an encryption request that omits the context or nonce of a convergent key.

### `ecdsa-sm2`

SM2 on the `sm2p256v1` curve. The same key can encrypt (SM2 public key
encryption), sign, and carry a certificate chain.

Signing covers an SM3 digest and the SM2 user identifier, which is part of the
`Z` value that the signature protects:

| Field | Behaviour |
| --- | --- |
| `uid` | User identifier mixed into the `Z` value. Defaults to the standard `1234567812345678`, so leaving it unset matches a plain SM2 implementation |
| `prehashed` | `true` when the input is already an SM3 digest. The `Z` value is not recomputed, so `uid` has no effect |
| `marshaling_algorithm` | `asn1` (default) for the DER `SEQUENCE { r, s }` that OpenSSL and X.509 use, or `jws` for the raw 64-byte `r‖s` in URL-safe base64 |

A signature only verifies with the identifier it was created with. Signatures
carry the key version (`vault:v1:…`), so verification uses the right version
automatically and rotation does not invalidate earlier signatures.

## Endpoint reference

All paths are relative to the mount, `gmsm` in the examples.

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `keys/:name` | Create a key, or update the configuration of an existing one |
| LIST | `keys` | List key names |
| GET | `keys/:name` | Read key metadata and the public keys of every version |
| DELETE | `keys/:name` | Delete a key; requires `deletion_allowed` |
| POST | `keys/:name/config` | Update key configuration |
| POST | `keys/:name/rotate` | Create a new key version |
| POST | `keys/:name/trim` | Remove versions below `min_available_version` |
| POST | `keys/:name/csr` | Generate a certificate request for a version |
| POST | `keys/:name/set-certificate` | Store an externally signed certificate chain |
| POST | `encrypt/:name` | Encrypt |
| POST | `decrypt/:name` | Decrypt |
| POST | `rewrap/:name` | Re-encrypt a ciphertext with the latest version |
| POST | `datakey/plaintext/:name`, `datakey/wrapped/:name` | Generate a data key |
| POST | `sign/:name` | Sign |
| POST | `verify/:name`, `verify/:name/:urlalgorithm` | Verify a signature, or an HMAC when `hmac` is supplied |
| POST | `hmac/:name`, `hmac/:name/:urlalgorithm` | Compute an HMAC-SM3 |
| POST | `hash`, `hash/:urlalgorithm` | Hash with SM3 |
| GET | `export/:type/:name`, `export/:type/:name/:version` | Export key material |
| GET | `backup/:name` | Back up a key |
| POST | `restore`, `restore/:name` | Restore a key |
| POST, GET | `config/keys` | Mount-wide key settings |
| POST, GET | `cache-config` | Size of the in-memory policy cache |

### Creating keys

```bash
vault write gmsm/keys/app-key type=ecdsa-sm2
vault write gmsm/keys/session-key derived=true convergent_encryption=true exportable=true
vault write gmsm/keys/mac-key type=hmac key_size=64
```

| Field | Applies to | Notes |
| --- | --- | --- |
| `type` | all | `sm4-gcm96` (default), `ecdsa-sm2`, `hmac` |
| `derived` | `sm4-gcm96` | Enables per-request key derivation |
| `convergent_encryption` | `sm4-gcm96` | Requires `derived` |
| `exportable` | all | Allows the private material to be exported |
| `allow_plaintext_backup` | all | Marks the key as eligible for plaintext backup |
| `auto_rotate_period` | all | Duration, `0` disables. Must be at least `1h` |
| `key_size` | `hmac` | Bytes, between 32 and 512 |

Reading a key returns its configuration, the versions it holds, and the public
key of each version:

```console
$ vault read gmsm/keys/app-key
Key                       Value
---                       -----
allow_plaintext_backup    false
auto_rotate_period        0s
deletion_allowed          false
derived                   false
exportable                false
keys                      map[1:map[certificate_chain: creation_time:2026-11-10T11:54:17+08:00 name:sm2p256v1 public_key:-----BEGIN PUBLIC KEY----- …]]
latest_version            1
min_decryption_version    1
min_encryption_version    0
name                      app-key
supports_decryption       true
supports_derivation       false
supports_encryption       true
supports_signing          true
type                      ecdsa-sm2
```

### Key configuration

`keys/:name/config` changes the settings that may still change after creation:
`min_decryption_version`, `min_encryption_version`, `deletion_allowed`,
`exportable`, `allow_plaintext_backup` and `auto_rotate_period`. Nothing below
`min_decryption_version` can be decrypted, wrapped or exported, which is the way
to retire a compromised version.

### Encryption

```bash
vault write gmsm/encrypt/mykey plaintext="$(printf 'secret' | base64)"
vault write gmsm/decrypt/mykey ciphertext=vault:v1:…
vault write gmsm/rewrap/mykey ciphertext=vault:v1:…
```

`encrypt` and `rewrap` accept `key_version` to pin the version to use; `decrypt`
takes the version from the ciphertext itself. All three accept `batch_input` for
a list of items, answered in `data.batch_results` in the order they were
supplied. `encrypt` and `decrypt` report a failing item in place, and
`partial_failure_response_code` chooses the status returned when only some items
fail.

`encrypt` creates a missing key on the fly, which is convenient for interactive
use and surprising in production. `config/keys` turns that off:

```bash
vault write gmsm/config/keys disable_upsert=true
```

### Data keys

```console
$ vault write -f gmsm/datakey/plaintext/mykey
Key            Value
---            -----
ciphertext     vault:v1:…
key_version    1
plaintext      …

$ vault write -f gmsm/datakey/wrapped/mykey
```

Both paths generate a random key and return it wrapped by the named key;
`datakey/plaintext/:name` also returns the base64 key itself, while
`datakey/wrapped/:name` never exposes it. `bits` selects the size of the data
key, one of 128, 256 or 512, and defaults to 128.

### Signing and verification

```console
$ vault write gmsm/sign/app-key input="$(printf 'hello' | base64)"
Key          Value
---          -----
signature    vault:v1:MEUCIQDf…

$ vault write gmsm/verify/app-key input="$(printf 'hello' | base64)" \
    signature=vault:v1:MEUCIQDf…
Key      Value
---      -----
valid    true
```

Signing with an identifier and verifying with the matching one:

```console
$ INPUT="$(printf 'hello' | base64)"
$ SIG="$(vault write -field=signature gmsm/sign/app-key input="$INPUT" uid=alice@example.com)"
$ vault write gmsm/verify/app-key input="$INPUT" signature="$SIG" uid=alice@example.com
Key      Value
---      -----
valid    true
```

Verification returns `valid=false` rather than an error when a signature simply
does not match, so callers have to inspect the field. `verify` also accepts an
`hmac` instead of a `signature`; `hash_algorithm` (or the deprecated `algorithm`)
selects the digest for that comparison and has no effect on signature
verification, which is always SM3.

### Hashing and HMAC

```console
$ vault write gmsm/hash input="$(printf 'abc' | base64)" format=hex
Key      Value
---      -----
sum      66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0

$ vault write gmsm/hmac/mac-key input="$(printf 'abc' | base64)"
Key      Value
---      -----
hmac     vault:v1:…
```

SM3 is the only hash algorithm exposed by this plugin, on `hash`, `hmac` and the
HMAC mode of `verify`. HMACs are versioned the same way signatures are, so
`vault:v1:…` still verifies after a rotation.

### Export

```bash
vault read gmsm/export/signing-key/app-key           # all versions
vault read gmsm/export/public-key/app-key/latest    # a single version
```

| `type` | Returns | Requires |
| --- | --- | --- |
| `encryption-key` | SM4 key (base64) or SM2 private key (PEM) | `exportable` |
| `signing-key` | SM2 private key (PEM) | `exportable` |
| `hmac-key` | HMAC key (base64) | `exportable` |
| `public-key` | SM2 public key (PEM) | nothing |
| `certificate-chain` | PEM bundle, leaf first | nothing |

## Certificates

The plugin holds the private key, so it cannot also act as the CA that signs it.
It produces the request instead, and stores the chain that comes back:

```console
$ vault write -field=csr gmsm/keys/app-key/csr version=1 > request.pem
# request.pem goes to your CA, which returns the signed chain
$ vault write gmsm/keys/app-key/set-certificate version=1 \
    certificate_chain="$(cat chain.pem)"
$ vault read gmsm/export/certificate-chain/app-key
```

- `keys/:name/csr` signs a PKCS#10 request with the stored key. Pass `csr` to
  supply a template: its subject, names, extensions and any other request
  attributes are carried over, while the public key and the signature always
  come from the selected key version. Without a template the request has an
  empty subject, which is what a caller that only holds a key needs.
- `keys/:name/set-certificate` accepts one or more concatenated PEM blocks, leaf
  first. The leaf's public key must belong to the selected key version; a chain
  for another key is rejected, so an export can never attest a key the mount
  does not hold. PEM blocks that are not certificates are ignored.
- The chain is stored per key version and handed back verbatim by
  `export/certificate-chain/:name`.

Certificates require a key type that can sign, which today means `ecdsa-sm2`.

## Differences from Vault transit

| | Transit | This plugin |
| --- | --- | --- |
| Symmetric algorithm | AES-128/256-GCM, ChaCha20-Poly1305 | SM4-GCM only |
| Asymmetric algorithm | ECDSA (P-256, P-384, P-521), RSA, Ed25519 | SM2 only |
| Hashing | SHA-2 family | SM3 only |
| Signing input hashing | Configurable | Always SM3, optionally over a pre-computed digest |
| User identifier | none | `uid` on sign and verify, mixed into the SM2 `Z` value |
| Key import | supported | not implemented |

Everything else — versioned ciphertexts and signatures, key derivation,
convergent encryption, associated data, batch requests, export, backup and
restore — follows the transit behaviour.

## Operational notes

- **Keys are protected by Vault's storage.** Storage entries for keys are marked
  for seal wrapping, so an enterprise deployment with a seal wrapper gets that
  protection; there is no separate wrapping step inside the plugin.
- **`deletion_allowed` is off by default.** `DELETE keys/:name` fails until it is
  enabled, which prevents an accidental delete from taking the key history with
  it.
- **Convergent encryption leaks equality.** Identical context and nonce produce
  identical ciphertexts by design; the nonce must be unique per context or the
  security of the ciphertext is compromised.
- **Batches are partial by default.** A batch that contains a bad item answers
  with the other results and marks the failure in place; pair it with
  `partial_failure_response_code` if the caller needs a non-200 status to notice.
- **The policy cache is per mount.** `cache-config` sets how many keys stay
  resident in memory; the default is unlimited and the minimum is 10.

## Development

```
gmsm/               backend, paths and key policy (the plugin itself)
internal/testca/    test-only SM2 CA that issues chains from certificate requests
scripts/ci/sm2ca/   CLI wrapper around internal/testca, used by the CI walkthrough
scripts/            build helpers
```

```bash
go build ./...
go vet ./...
go test ./...
```

`go test ./...` is self-contained: the REST test skips unless `VAULT_ADDR` and
`VAULT_TOKEN` are set. To run it against a real mount:

```bash
export VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root GMSM_MOUNT=gmsm
go test -count=1 -run TestRESTAPI -v ./gmsm
```

The test covers status codes, JSON field names and the shape of error responses
that the CLI hides, and mirrors what a client actually depends on.

Continuous integration runs two jobs. `build` runs the unit tests. `Integration
Test` builds the plugin, installs Vault, starts a dev server, replays the
walkthrough from this document, adds the certificate and `uid` checks, and runs
the REST test against the same server.

## License

This plugin is distributed under the MIT license; see [LICENSE](LICENSE).

The shape of its request and response fields follows the transit secrets engine
of HashiCorp Vault, which was published under MPL-2.0 up to release 1.14.0. The
parts of `gmsm/` that originate from those releases are therefore also available
under the MPL-2.0. Releases 1.15.0 and later of that repository are licensed
under BUSL-1.1 and are deliberately not used as a source here.
