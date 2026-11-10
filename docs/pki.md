# Certificate authority plugin (`pki-gmsm`)

`pki-gmsm` is a certificate authority, not a transit engine: it generates SM2
keys, signs X.509 certificates with `SM2WithSM3` and publishes a CRL. It is a
mount type of its own, because Vault binds one plugin to one mount and because
the lifecycle of a CA has nothing in common with that of a transit key.

It is mounted separately from the [transit engine](transit.md), under a path of
its own:

```bash
PLUGIN_NAME=pki-gmsm
CHECKSUM=$(sha256sum "$PLUGIN_DIR/$PLUGIN_NAME" | cut -d' ' -f1)

vault plugin register -sha256="$CHECKSUM" secret pki-gmsm
vault secrets enable -path=pki-gmsm pki-gmsm
```

The binary and the registered name are the same string, because Vault looks for
`$PLUGIN_DIR/<registered name>` and does not try a prefixed variant. The mount
path is free to choose and is `pki-gmsm` here, so it does not collide with the
built-in `pki` engine, which usually already occupies `pki/`. Every path below
is relative to the mount.

A mount holds one authority and signs with it unless a role names another one.
`issuers` lists the authorities the mount holds and `issuer/:ref` reads one,
addressed by identifier, by name or by the word `default`, answering with
whether it is the one in use. Rotation is not implemented yet, so the mount can
only hold the authority it was generated with, and generating a second one over
it is refused: the certificates already issued would stop verifying against it.

## Contents

- [Certificate authority plugin (`pki-gmsm`)](#certificate-authority-plugin-pki-gmsm)
  - [Contents](#contents)
  - [Generating the authority](#generating-the-authority)
  - [Roles](#roles)
    - [Role names and storage](#role-names-and-storage)
    - [A certificate for signing only](#a-certificate-for-signing-only)
  - [Issuing and signing](#issuing-and-signing)
  - [Reading, revoking and the CRL](#reading-revoking-and-the-crl)
  - [An intermediate authority](#an-intermediate-authority)
  - [Differences from Vault pki](#differences-from-vault-pki)

## Generating the authority

```console
$ vault write pki-gmsm/root/generate/internal common_name="Example Root CA" ttl=87600h
Key            Value
---            -----
certificate    -----BEGIN CERTIFICATE-----…
issuing_ca     -----BEGIN CERTIFICATE-----…
ca_chain       [-----BEGIN CERTIFICATE-----…]
serial_number  1F:2C:0E:…
expiration     1798761600
issuer_id      c8f1…
key_id         3a02…
```

`internal` keeps the private key inside the mount and never returns it;
`exported` returns it once in the response, in SEC 1 (`private_key_format=der`,
the default) or PKCS#8 form. The validity defaults to ten years and
`max_path_length` defaults to `-1`, which allows any depth of intermediates
below it.

The authority certificate carries an SM3 subject key identifier and names the
same value as its authority key identifier, which is what a self-signed
certificate needs to terminate a chain. `ca`, `ca/pem` (raw
`application/pem-encoding`) and `ca_chain` read it back.

`DELETE pki-gmsm/root` removes the authority, its keys, every certificate it
issued and the cached CRL. Roles survive, because they are policy rather than
state of the authority. Each authority keeps its own CRL, so a revocation names
the list of the authority that signed the certificate even after the mount has
moved on.

## Roles

A role is the policy that decides what may be issued. Nothing is signed before
the request has passed it, so a refused request never leaves a certificate
behind.

```console
$ vault write pki-gmsm/roles/web allowed_domains=example.com allow_subdomains=true \
    ttl=24h max_ttl=720h
```

`roles/:name` answers `PATCH` too. See
[Role names and storage](#role-names-and-storage) for the difference between a
write and a patch. `roles` lists the names.

| Group | Fields |
| --- | --- |
| Validity | `ttl` (720h), `max_ttl` (8760h), `not_before_duration` (30s of backdating) |
| Names | `allowed_domains`, `allow_bare_domains`, `allow_subdomains`, `allow_glob_domains`, `allow_any_name`, `allow_wildcard_certificates`, `allow_localhost`, `enforce_hostnames`, `require_cn` (on), `cn_validations` (`email,hostname`), `allowed_uri_sans`, `allow_ip_sans` |
| Subject | `organization`, `ou`, `country`, `locality`, `province`, `street_address`, `postal_code`, `serial_number` (the OID 2.5.4.5 value, not the certificate serial) |
| Usage | `key_usage` (`DigitalSignature,KeyAgreement`), `ext_key_usage`, `ext_key_usage_oids`, `server_flag`, `client_flag`, `code_signing_flag`, `email_protection_flag` |
| Storing | `no_store`, `generate_lease` |
| Signing | `issuer_ref` (`default`), resolved to an identifier or a name when a certificate is issued |

A name is accepted when it matches one of the three independent modes of
`allowed_domains`: `allow_bare_domains` for the domain itself, `allow_subdomains`
for a name below it, and `allow_glob_domains` to read the entries as glob
patterns. An email address takes the same route with its domain part, so
`user@example.com` needs `allow_bare_domains`, while `user@mail.example.com`
needs `allow_subdomains`. A wildcard is checked whole, asterisk included, so
`*.example.com` is covered by `allow_subdomains` and not by
`allow_bare_domains`.

### Role names and storage

A role name is the key its record is stored under, `role/<name>`, so a name
addresses exactly one policy. It is unique only within the mount: the same name
in another mount is an unrelated record, and the name never reaches the
certificate. The path accepts `\w(([\w-.]+)?\w)?`, so letters, digits, `_` and
interior `-` or `.` are allowed, `/` is not, and names are case-sensitive:
`signing` and `Signing` are two roles.

A write replaces the record as a whole, so restating one field resets the others
to their defaults:

```bash
# Wrong: the role keeps key_usage and loses server_flag, ttl, ...
vault write pki-gmsm/roles/signing key_usage=DigitalSignature

# Right: only key_usage changes
vault patch pki-gmsm/roles/signing key_usage=DigitalSignature
```

A patch of a role that does not exist is a no-op rather than an error.

### A certificate for signing only

A leaf that only signs data needs no subject alternative names and no TLS
usages, and its common name is usually not a host name:

```bash
vault write pki-gmsm/roles/signing \
    key_usage=DigitalSignature \
    server_flag=false client_flag=false code_signing_flag=true \
    allow_any_name=true enforce_hostnames=false \
    ttl=720h max_ttl=8760h

vault write pki-gmsm/issue/signing common_name="Example Release Signing 2026" \
    exclude_cn_from_sans=true
```

- `key_usage` drops the default `KeyAgreement`. Signing needs
  `DigitalSignature`; `ContentCommitment` can be added for non-repudiation.
- `server_flag=false client_flag=false` remove `serverAuth` and `clientAuth`, so
  the certificate is not a TLS certificate even if a peer tries to use it as
  one.
- `code_signing_flag=true` is the extended usage that fits signing code. For
  signing documents instead, leave every flag off and the certificate carries no
  extended usage at all, which leaves the decision to the relying party; or name
  the usages explicitly, including RFC 9336's document signing OID
  (`ext_key_usage_oids=1.3.6.1.5.5.7.3.36`).
- `allow_any_name=true` removes the domain policy. `enforce_hostnames=false` is
  what lets the common name be free text: the host name check runs even under
  `allow_any_name`, so a name with spaces in it is refused until it is turned
  off. `cn_validations` is not consulted under `allow_any_name`.
- `exclude_cn_from_sans=true` on the issue call keeps the common name out of the
  subject alternative names, which would otherwise receive it as a DNS name.

If the key lives in an HSM or another signer, use `sign/:role` with a
certificate request instead of `issue/:role`, so the private key never reaches
the mount.

## Issuing and signing

| Path | Purpose |
| --- | --- |
| `issue/:role` | generates an SM2 key and returns it with the certificate |
| `sign/:role` | signs a request the caller already holds the key for |

Both accept `common_name`, `alt_names`, `ip_sans`, `uri_sans`, `ttl`,
`exclude_cn_from_sans` and `format` (`pem`, `der`, or `pem_bundle` where a
private key comes with the certificate). `issue` adds `private_key_format` (`der`
for SEC 1, `pkcs8`) and `key_type`; `sign` takes the `csr` as PEM or base64
encoded DER, verifies its signature, and refuses a key that is not an SM2 key.

```console
$ vault write pki-gmsm/issue/web common_name=web.example.com alt_names=api.example.com
```

An entry of `alt_names` that contains `@` becomes an email address, everything
else a DNS name. The common name is copied into the subject alternative names
unless `exclude_cn_from_sans` is set, because the clients that matter read the
SANs and ignore the CN. The role decides whether the common name and the names
of a request to sign are taken over (`use_csr_common_name`, `use_csr_sans`), and
what was written in the request itself wins over the request.

`issue` returns the private key once and keeps only the certificate, unless the
role sets `no_store`.

## Reading, revoking and the CRL

| Path | Purpose |
| --- | --- |
| `cert/:serial` | one issued certificate, with `revocation_time` once revoked |
| `certs` (LIST) | the serial numbers the mount kept |
| `revoke` | takes `serial_number`; revoking twice answers the original time |
| `crl` | the CRL as JSON: `certificate`, `number`, `this_update`, `next_update` |
| `crl/pem`, `crl/der` | the same CRL as a raw body (`application/pem-encoding`, `application/pkix-crl`) |
| `crl/rotate` | rebuilds the CRL under the next number |
| `config/urls` | `issuing_certificates`, `crl_distribution_points`, `ocsp_servers` |
| `tidy` | drops expired certificates and revocations |

Serial numbers are 128 random bits, reported as colon separated uppercase hex
and accepted with or without the colons, in either case.

The CRL is cached as DER in storage, because an SM2 signature is randomised: a
CRL rebuilt on every read would carry a different signature each time and no
client could cache it. Writing a revocation marks the cache dirty and the next
read rebuilds it, so `revoke` alone never pays for a signature nobody asked for.
`crl/rotate` forces a rebuild, and `tidy` is what keeps the revoked list from
growing forever.

`tidy` runs synchronously and answers with what it removed. It takes
`safety_buffer` (72h), `tidy_cert_store` (off) and `tidy_revoked_certs` (on).

## An intermediate authority

A second mount becomes an intermediate of the first in two steps. The first
mount never sees the key of the second:

```console
$ vault write pki-gmsm/root/sign-intermediate csr=@intermediate.pem \
    common_name="Example Issuing CA"
$ vault write pki-int/intermediate/set-signed certificate=@signed.pem
```

`intermediate/generate/internal` on the second mount stores the key and answers
with `csr` and `key_id`; `intermediate/set-signed` then verifies that the
certificate is a CA, that it carries the public key of the pending request, and
that it is signed by the certificate supplied with it, before that chain becomes
the authority of the mount. `root/sign-intermediate` clamps the validity to the
remaining validity of the signing authority, with a warning.

## Differences from Vault pki

| | Vault pki | This plugin |
| --- | --- | --- |
| Key algorithm | RSA, ECDSA, Ed25519 | SM2 only |
| Certificate signature | SHA-2 family | `SM2WithSM3` only |
| Subject key identifier | SHA-1 of the public key, RFC 5280 method 1 | SM3 of the public key, truncated to 160 bits |
| Issuers | Many, addressed by name or identifier, with rotation and cross-signing | One per mount, addressed by identifier or name; rotation is not implemented, and the authority is replaced by deleting it |
| Lease | Optional per-certificate lease | Not implemented; `generate_lease` only produces a warning |
| `no_store` | The certificate is kept nowhere and cannot be revoked by serial | The metadata is kept, so the serial stays revocable |
| Tidy | Asynchronous, with a status endpoint | Synchronous, and it answers with what it removed |
| CRL | Rebuilt on demand, cached in memory | Cached as DER in storage, because the signature is randomised |
| OCSP | `ocsp_enable` and a responder | `ocsp_servers` is stored; nothing serves OCSP |
| ACME, EST, CRL building from a fixed list | supported | not implemented |

Everything else — roles, the name policy, issue and sign, serial and certificate
storage, revocation, the CRL endpoints and `config/urls` — follows the pki
behaviour, with the names of the fields unchanged.
