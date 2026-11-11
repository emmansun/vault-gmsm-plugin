# Transit engine reference

English | [简体中文](transit.zh-CN.md)

The `gmsm` mount is a transit secrets engine for SM4-GCM encryption and SM2
signing. Keys are generated inside Vault, or imported from material you already
hold, and never leave the mount unless the key is marked exportable.

Its request and response shapes follow the transit secrets engine of Vault 1.14,
so existing transit tooling, policies and client libraries carry over with the
mount path changed. What is not the same is listed in
[Differences from Vault transit](#differences-from-vault-transit).

Installation and a quick start are in the [README](../README.md).

## Contents

- [Transit engine reference](#transit-engine-reference)
  - [Contents](#contents)
  - [Key types](#key-types)
    - [`sm4-gcm96`](#sm4-gcm96)
    - [`sm2`](#sm2)
  - [Endpoint reference](#endpoint-reference)
    - [Creating keys](#creating-keys)
    - [Key configuration](#key-configuration)
    - [Encryption](#encryption)
    - [Data keys](#data-keys)
    - [Signing and verification](#signing-and-verification)
    - [Hashing and HMAC](#hashing-and-hmac)
    - [Export](#export)
  - [Certificates](#certificates)
  - [Importing keys](#importing-keys)
  - [Differences from Vault transit](#differences-from-vault-transit)
  - [Not implemented](#not-implemented)

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

### `sm2`

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
| POST | `keys/:name/import` | Create a key from imported key material |
| POST | `keys/:name/import_version` | Add a version to an imported key |
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
vault write gmsm/keys/app-key type=sm2
vault write gmsm/keys/session-key derived=true convergent_encryption=true exportable=true
vault write gmsm/keys/mac-key type=hmac key_size=64
```

| Field | Applies to | Notes |
| --- | --- | --- |
| `type` | all | `sm4-gcm96` (default), `sm2`, `hmac` |
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
type                      sm2
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

Certificates require a key type that can sign, which today means `sm2`. To have
the same mount issue the certificate instead, use the
[certificate authority plugin](pki.md).

## Importing keys

`keys/:name/import` creates a key from material that was generated elsewhere,
and `keys/:name/import_version` adds further material to a key that was itself
imported. Both take the material in the request body, so the transport has to be
trusted; transit's wrapping-key exchange and `byok-export` are not implemented.

```bash
vault write gmsm/keys/imported/import type=sm2 private_key=@private.pem
vault write gmsm/keys/imported/import_version private_key=@next.pem
```

| Field | Path | Notes |
| --- | --- | --- |
| `type` | `import` | `sm2`, `sm4-gcm96` or `hmac`. Required |
| `private_key` | both | `sm2` only. PEM, either PKCS#8 (`BEGIN PRIVATE KEY`) or SEC 1 (`BEGIN EC PRIVATE KEY`) |
| `public_key` | both | `sm2` only. PEM SPKI (`BEGIN PUBLIC KEY`) |
| `key` | both | `sm4-gcm96` and `hmac` only. Base64, 16 bytes for SM4 and 32–512 for HMAC |
| `exportable` | `import` | Allows the material to be exported again |
| `allow_plaintext_backup` | `import` | Allows a plaintext backup |
| `allow_rotation` | `import` | Allows `rotate` to replace the imported version with a generated one. Off by default |
| `auto_rotate_period` | `import` | Requires `allow_rotation`, and must be at least `1h` |
| `version` | `import_version` | Completes the version that holds only a public key |

The rules the paths enforce:

- `import` only creates. It answers `already exists` for a name that is taken,
  pointing at `import_version`, so a typo cannot splice external material onto an
  existing key.
- `import_version` only works on imported keys. A key created by Vault refuses
  further material, and so does an imported key that has already been rotated
  inside Vault: its ring then holds generated versions, and mixing the two is
  refused rather than done quietly.
- A version that holds only a public key can be used for `verify` and `encrypt`.
  `sign` and `decrypt` fail with "does not contain a private part" until
  `import_version` supplies the private key; the public key has to match the one
  stored for that version, which is what makes the completion safe.
- What `export/signing-key` and `export/encryption-key` produce can be passed
  straight back to `import`, which is how a key moves between mounts.
- An imported key reports `imported_key=true`, plus
  `imported_key_allow_rotation` when rotation was allowed.
- `keys/:name/config` refuses an `auto_rotate_period` on an imported key that did
  not allow rotation, because that rotation could never happen.

After a rotation the imported material stays on the mount as the older versions,
so decrypting and verifying with it keeps working until
`min_decryption_version` retires it.

## Differences from Vault transit

| | Transit | This plugin |
| --- | --- | --- |
| Symmetric algorithm | AES-128/256-GCM, ChaCha20-Poly1305 | SM4-GCM only |
| Asymmetric algorithm | ECDSA (P-256, P-384, P-521), RSA, Ed25519 | SM2 only |
| Hashing | SHA-2 family | SM3 only |
| Signing input hashing | Configurable | Always SM3, optionally over a pre-computed digest |
| User identifier | none | `uid` on sign and verify, mixed into the SM2 `Z` value |
| Key import | supported | `import` and `import_version`, with plaintext material only: no wrapping key, and `import_version` stops once the key has been rotated in Vault |
| Secure key transfer | `wrapping_key`, `byok-export` and `import` of a wrapped `ciphertext` | not implemented; `export`, `import` and `backup` all move material in plaintext |

Everything else — versioned ciphertexts and signatures, key derivation,
convergent encryption, associated data, batch requests, export, backup and
restore — follows the transit behaviour.

The secure transfer row is the deliberate omission. Transit's `wrapping_key` and
`byok-export` exist so a key can move between two Vault instances without either
operator handling plaintext, but `byok-export` is only useful together with an
`import` that accepts the wrapped `ciphertext` it produces, and that half needs a
wrapping keypair owned by the mount. Neither is implemented here, so moving a key
in or out relies on TLS, on `exportable` and `allow_plaintext_backup`, and on the
operator handling the material only where it is meant to be handled.

## Not implemented

The following are deliberately rejected rather than half-implemented:

- `sm4-cmac` keys — creation fails with `sm4-cmac keys are not supported by this plugin`.
- Encryption, decryption and signing with a key type that does not support them.
