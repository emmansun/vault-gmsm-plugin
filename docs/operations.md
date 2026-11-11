# Operations

Running, installing and building the two plugins. The feature references are
[transit](transit.md) and [certificate authority](pki.md).

## Contents

- [Compatibility](#compatibility)
- [Installation](#installation)
  - [From a release](#from-a-release)
  - [From source](#from-source)
- [Releasing](#releasing)
- [Operational notes](#operational-notes)
- [Development](#development)

## Compatibility

| | |
| --- | --- |
| Vault | 2.1.1 (exercised in CI), 1.17.3 (exercised manually) |
| Go | 1.26 or later, for building from source |
| Plugin protocol | Multiplexed gRPC plugin; the registered name has to match the binary file name |

The plugins are built against the Vault 2.1.1 module set. Both are standard
`logical.TypeLogical` backends, so they can be mounted and unmounted like any
other secrets engine.

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
plugin directory, including the `.exe` suffix on Windows: Vault looks for
`<plugin_directory>/<registered name>` and does not try a `vault-plugin-secrets-`
prefixed variant. The certificate authority is installed the same way, under its
own plugin name and mount path:

```bash
PLUGIN_NAME=pki-gmsm
CHECKSUM=$(sha256sum "$PLUGIN_DIR/$PLUGIN_NAME" | cut -d' ' -f1)

vault plugin register -sha256="$CHECKSUM" secret pki-gmsm
vault secrets enable -path=pki-gmsm pki-gmsm
```

### From source

```bash
./scripts/build.sh   # both plugins, linux/amd64 and windows/amd64 into pkg/<os>_<arch>/
```

Each output directory is accompanied by a `.sha256sum` file, which is what the
`-sha256` flag above expects. Every build produces two binaries:
`vault-gmsm-plugin` for the transit engine, and `pki-gmsm` for the certificate
authority: the file name is the name the plugin is registered under, so the two
have to be kept in step. On Windows, `scripts\build.bat` writes
`plugin\vault-gmsm-plugin.exe` next to `plugin\plugin.sha256sum`, and
`plugin\pki-gmsm.exe` next to `plugin\pki-gmsm.sha256sum`.

## Releasing

A release is one tag for the repository, and both plugins are published under
it: `vault-gmsm-plugin-vX.Y.Z-<os>-<arch>` for the transit engine and
`pki-gmsm-vX.Y.Z-<os>-<arch>` for the certificate authority, each with a
`.sha256` beside it.

The version belongs to the module rather than to either plugin, which is
deliberate: both binaries are built from the same `go.mod` and the same commit,
so a tag that moved only one of them would describe a state that never existed
to anyone who looks at the repository. The cost is that a change to one plugin
increases the version of the other as well, so the release notes are where the
difference is recorded, by naming the plugin that changed.

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
- **Key material moves in plaintext.** `export`, `import` and `backup` carry
  material in a request or a response, so the path in between has to be trusted:
  TLS to Vault, no response logging, no key files left behind. Transit's
  wrapping-key exchange and `byok-export` are not implemented, and `exportable`
  plus `allow_plaintext_backup` are what decide whether those plaintext routes
  exist at all.
- **The authority is a single object per mount.** Generating a second root over
  an existing one is refused, and `DELETE pki-gmsm/root` is the only way to
  replace it: it takes the issued certificates and the cached CRL with it.
- **The CRL is signed lazily.** A revocation marks the cached CRL dirty and the
  next read rebuilds it, so an unused mount never pays for a signature it did
  not ask for.
- **A revocation list drops a certificate once it expires.** The list names the
  certificates a client may still be shown, so entries of expired certificates
  leave it at the next signature and the list does not grow between tidies. The
  records behind them are kept, and `tidy` is what removes those: schedule it,
  nightly for a mount that issues every day and weekly for one whose
  certificates live for weeks, or the mount keeps every certificate it ever
  issued.
- **Signing runs beside signing in the pki plugin.** Certificates, lists and
  answers are signed under a shared read lock, so requests that only sign do
  not queue behind each other; a revocation, a rotation or an import is what
  takes the lock for itself.

## Development

```
gmsm/                transit backend, paths and key policy (one plugin)
pki/                 certificate authority backend, paths and name policy (the other)
main.go              the transit plugin binary
cmd/pki-gmsm/        the certificate authority plugin binary
internal/testca/     test-only SM2 CA that issues chains from certificate requests
internal/ocspclient/ the OCSP client the tests and the CI walkthrough share
scripts/ci/sm2ca/    CLI wrapper around internal/testca, used by the CI walkthrough
scripts/ci/pkicheck/ certificate and OCSP checks the CI walkthrough runs
scripts/             build helpers
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

Continuous integration runs three jobs. `build` runs the unit tests of both
plugins. `Integration Test` builds the transit plugin, installs Vault, starts a
dev server, replays the walkthrough from the [README](../README.md), adds the
certificate and `uid` checks, and runs the REST test against the same server.
`PKI Integration Test` does the same for the certificate authority: it generates
an authority, writes a role, issues a certificate and verifies it with
`scripts/ci/pkicheck`, asks the responder about the certificate while it is good
and again once it is revoked, reads the CRL back in each of its three forms,
runs `tidy`, rotates the authority, verifies that the authority it replaced
still publishes the list that names the revocation, and switches back to it.
