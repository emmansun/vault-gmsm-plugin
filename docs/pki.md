# Certificate authority plugin (`pki-gmsm`)

`pki-gmsm` is a certificate authority, not a transit engine: it generates SM2
keys, signs X.509 certificates with `SM2WithSM3`, publishes a CRL and answers
OCSP status queries. It is a mount type of its own, because Vault binds one
plugin to one mount and because the lifecycle of a CA has nothing in common
with that of a transit key.

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

A mount holds the authorities it was given, and signs with one of them: the
first it generated or imported, or the one selected with `issuer/:ref/default`.
`issuers` lists them and `issuer/:ref` reads one, addressed by identifier, by
name or by the word `default`, answering with whether it is the one in use.
`root/rotate/:type` generates a new authority beside the old one and signs with
it from then on; the old one stays, so the certificates it signed keep verifying
and its list keeps reporting its revocations. `DELETE /issuer/:ref` retires one,
but only once its certificates have expired. `config/ca` adopts an authority
that was created elsewhere.

## Contents

- [Certificate authority plugin (`pki-gmsm`)](#certificate-authority-plugin-pki-gmsm)
  - [Contents](#contents)
  - [Generating the authority](#generating-the-authority)
  - [Rotating, retiring and importing one](#rotating-retiring-and-importing-one)
    - [An external signer](#an-external-signer)
    - [What an authority may do](#what-an-authority-may-do)
  - [Roles](#roles)
    - [Role names and storage](#role-names-and-storage)
    - [A certificate for signing only](#a-certificate-for-signing-only)
    - [What the certificate states](#what-the-certificate-states)
  - [Issuing and signing](#issuing-and-signing)
  - [Reading, revoking and the CRL](#reading-revoking-and-the-crl)
    - [Delta CRLs](#delta-crls)
  - [The responder (OCSP)](#the-responder-ocsp)
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
moved on. A mount that has been rotated holds more than one authority, and this
delete is refused there: retire them one at a time, as described below.

## Rotating, retiring and importing one

A rotation adds an authority and leaves the one it replaces in place:

```console
$ vault write pki-gmsm/root/rotate/internal common_name="Example Root CA 2026"
Key                 Value
---                 -----
certificate         -----BEGIN CERTIFICATE-----…
issuer_id           4b1d…
previous_issuer_id  c8f1…
```

The mount signs with the new authority from then on. The old one answers on
`issuer/:ref` and still signs for a role whose `issuer_ref` names it, which is
what lets the certificates issued under it keep their own authority — and their
own list, on `issuer/:ref/crl` — for as long as they are valid.
`issuer/:ref/default` moves the mount back to one of them:

```console
$ vault write -f pki-gmsm/issuer/c8f1…/default
```

| Path | Purpose |
| --- | --- |
| `root/rotate/:type` | generates a new self-signed authority and signs with it |
| `POST issuer/:ref` | changes its name, what its key may do, and the addresses it publishes |
| `issuer/:ref/json`, `/pem`, `/der` | the authority as one JSON document, as PEM, or as DER |
| `issuer/:ref/default` | makes one of the authorities the one in use |
| `issuer/:ref/issue/:role`, `/sign/:role` | issues or signs with that authority, whatever the role names |
| `DELETE issuer/:ref` | retires one authority, once its certificates have expired |
| `config/ca` | adopts a certificate, the chain above it and, optionally, the private key, or names the provider that holds one |

Retiring an authority removes its key, its cached list, the revocations it
recorded and the certificates it issued; the mount signs with another one
afterwards. It is refused while a certificate of that authority has not expired,
because the list that would have reported its revocation goes with it.
`DELETE /root` still removes everything, and it refuses a mount that has been
rotated: retire the authorities one at a time until one is left.

`config/ca` is the way in for an authority created elsewhere, offline or by
another tool. The bundle carries the certificate, the certificates above it and,
when the mount is to sign itself, the private key that belongs to it. The
certificate has to be a CA, the chain has to sign in order, and a key in the
bundle has to be the one the certificate carries; anything else is refused
before it is stored.

```console
$ vault write pki-gmsm/config/ca pem_bundle=@authority.pem
$ vault write pki-gmsm/config/ca pem_bundle=@authority-cert.pem \
    provider=pkcs11 reference=ca-key
```

### An external signer

A key that may not leave an HSM, a PKCS#11 token or a key management service can
still be the one the mount signs with. Import the certificate without a key and
name the provider that holds it:

```bash
vault write pki-gmsm/config/ca pem_bundle=@authority-cert.pem \
    provider=pkcs11 reference=ca-key
```

The reference is whatever the provider needs to find the key. It is recorded
with the authority and read every time it signs. The mount asks the provider
during the import and refuses a key the certificate does not carry, so it never
ends up signing certificates that verify only against themselves. Every
signature works the same way afterwards: the certificate, the list, the delta
and the answer of the responder all reach the appliance, and the private key
never enters Vault.

The mount cannot generate an authority with such a key, because it cannot ask an
appliance to create one. The appliance makes the key and its certificate, and
`config/ca` adopts them.

A provider is a Go implementation, because talking to an appliance takes the
library of the appliance. It is registered by the program that embeds the
plugin, before it starts serving:

```go
provider := pkcs11.Provider{Module: "/usr/lib/softhsm2.so"}
if err := pki.RegisterSignerProvider("pkcs11", provider); err != nil {
    log.Fatal(err)
}
```

It refuses an empty name, a missing provider and a name that is already taken,
which makes a second registration of the same appliance a startup error rather
than a silent choice between two.

The interface is an `issuerKey`: a `crypto.Signer`, a `crypto.MessageSigner` and
a `Close`. The message signer is the part that makes the seam usable at all. An
SM2 signature covers a digest that includes the public key and the identifier of
the signer, so a key handed a digest computed elsewhere could only answer with a
signature nobody can check. `Public` and `Sign` are what the builders of
certificates and lists ask of a key.

`Close` is the part that would have been expensive to add later. The mount
resolves a signer for each signature and closes it as soon as it has the bytes,
so a session of a token or a connection to a key management service does not
outlive the request that needed it: a provider that keeps a pool of either gets
the signer back there. The mount closes a signer it refuses as well, which is
where a provider answering with the wrong key would otherwise hold a session for
every refused request. A close that fails is recorded rather than failing a
request that already has its signature.

Nothing in the interface carries a context, because the builders of certificates
and lists hand a signer bytes and no deadline. A provider that talks over a
network applies a time limit of its own.

Nothing in this repository registers a provider, which is why a stock build
signs only with the keys it holds. The failure worth knowing about is a
provider that starts answering with a different key: the mount checks that key
against the certificate on every signature and refuses, rather than issue a
certificate no client could verify.

### What an authority may do

An authority is more than its certificate: what its key may be used for, how it
treats a certificate that would outlive it, and the addresses its certificates
publish all belong to it, and `POST issuer/:ref` changes them. Only the fields of
the request change, so a write that sets one of them leaves the rest alone.

```console
$ vault write pki-gmsm/issuer/c8f1… issuer_name=primary \
    usage=issuing-certificates,crl-signing,ocsp-signing \
    leaf_not_after_behavior=truncate \
    crl_distribution_points=https://ca.example.com/crl
```

`issuer_name` is what the authority is addressed by from then on, on any path
that takes a `ref`. `usage` is what its key may do: `issuing-certificates`,
`crl-signing` and `ocsp-signing`. An authority that was never given one may do
all three, which is what keeps a mount written before the field existed working;
`read-only` refuses all of them. A request that asks for something the authority
may not do is refused with 400 — and the responder answers `unauthorized` in the
protocol instead, because a client of OCSP cannot read an error of the API.

`leaf_not_after_behavior` decides what happens to a certificate that would be
valid past the authority. `truncate` shortens it with a warning and is the
default, `err` refuses the request and names both dates, and `permit` lets it
stand, which is what a mount in front of a longer-lived authority needs.

The three address lists — `issuing_certificates`, `crl_distribution_points` and
`ocsp_servers` — override `config/urls` one list at a time, which is how a mount
that holds more than one authority points each certificate at the list of the
authority that signed it. An empty list returns that one to the mount-wide
address:

```bash
vault write pki-gmsm/issuer/$ISSUER_ID crl_distribution_points=""
```

`issuer/:ref/json` is the document to keep when the authority has to be
reproduced elsewhere: it carries the certificate, the chain above it and the
settings that are not part of the certificate. `issuer/:ref/pem` and
`issuer/:ref/der` serve the certificate alone, as a raw body.

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
| Validity | `ttl` (720h), `max_ttl` (8760h), `not_before_duration` (30s of backdating), `not_after` (no deadline of its own) |
| Names | `allowed_domains`, `allow_bare_domains`, `allow_subdomains`, `allow_glob_domains`, `allow_any_name`, `allow_wildcard_certificates`, `allow_localhost`, `enforce_hostnames`, `require_cn` (on), `cn_validations` (`email,hostname`), `allowed_uri_sans`, `allowed_other_sans`, `allow_ip_sans` |
| Profile | `policy_identifiers` (none): the certificate policies the certificate states |
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

### What the certificate states

Three fields decide what a certificate says about itself, and none of them is
inferred from anything around it:

- `policy_identifiers` are the certificate policies the certificate states, as
  dotted decimal OIDs. A certificate of a role that names none states none.
  Only the identifiers are written, because a qualifier points at a document
  this mount cannot vouch for.
- `not_after` is the last moment a certificate of the role may be valid, written
  in RFC 3339 form. It is a deadline rather than a longer validity: a request
  that asks for more is shortened to it, with a warning, and one made after it
  is refused. The remaining validity of the authority clamps on top of it.
- `allowed_other_sans` are the `otherName` entries a request may ask for, as
  `OID;form:value` entries with glob patterns allowed. The request names what it
  wants in `other_sans` on the issue or sign call, and the role decides which of
  them are accepted.

```bash
vault write pki-gmsm/roles/staff policy_identifiers=2.23.140.1.2.1 \
    allowed_other_sans="1.3.6.1.4.1.311.20.2.3;utf8:*"

vault write pki-gmsm/issue/staff common_name=alice@example.com \
    other_sans="1.3.6.1.4.1.311.20.2.3;utf8:alice@example.com"
```

The form is `utf8` or `ia5`, whichever the identifier expects, and a value is
checked against it both when the role is written and when the name is asked
for. The whole entry is matched against the pattern, so the identifier, the form
and the value all have to agree.

## Issuing and signing

| Path | Purpose |
| --- | --- |
| `issue/:role` | generates an SM2 key and returns it with the certificate |
| `sign/:role` | signs a request the caller already holds the key for |
| `issuer/:ref/issue/:role`, `issuer/:ref/sign/:role` | the same, from the authority the path names |

Both accept `common_name`, `alt_names`, `ip_sans`, `uri_sans`, `other_sans`,
`ttl`, `exclude_cn_from_sans` and `format` (`pem`, `der`, or `pem_bundle` where
a private key comes with the certificate). `issue` adds `private_key_format`
(`der` for SEC 1, `pkcs8`) and `key_type`; `sign` takes the `csr` as PEM or
base64 encoded DER, verifies its signature, and refuses a key that is not an SM2
key.

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

The two forms with an authority in the path sign with it whatever the role
names: the ref of the path wins over `role.issuer_ref`. That is how a
certificate is still issued from the authority a mount has rotated away from,
without a role that pins every request to it.

Signatures do not queue behind each other. A certificate, a list and an answer
are signed under a shared read lock, so requests that only sign run beside each
other rather than one at a time. What takes the lock for itself is a change: a
revocation, a rotation, an import or a write to an authority.

## Reading, revoking and the CRL

| Path | Purpose |
| --- | --- |
| `cert/:serial` | one issued certificate, with `revocation_time` and `revocation_reason` once revoked |
| `certs` (LIST) | the serial numbers the mount kept |
| `certs/revoked` (LIST) | the serial numbers the mount revoked |
| `revoke` | takes `serial_number` or the `certificate` itself, and an RFC 5280 `revocation_reason` |
| `crl` | the CRL as JSON: `certificate`, `number`, `this_update`, `next_update` |
| `crl/pem`, `crl/der` | the same CRL as a raw body (`application/pem-encoding`, `application/pkix-crl`) |
| `crl/rotate` | rebuilds the CRL under the next number |
| `crl/delta`, `/delta/pem`, `/delta/der` | the changes since the full list, with `base_number` in the JSON form |
| `crl/rotate-delta` | rebuilds the changes under the next number of the delta |
| `issuer/:ref/crl`, `/pem`, `/der` | the list of one authority, signed by it |
| `issuer/:ref/crl/rotate` | rebuilds that authority's list under its own number |
| `issuer/:ref/crl/delta`, `/delta/pem`, `/delta/der` | the changes since that authority's full list |
| `issuer/:ref/crl/rotate-delta` | rebuilds that authority's changes |
| `config/urls` | `issuing_certificates`, `crl_distribution_points`, `ocsp_servers` |
| `config/crl` | `expiry` and `auto_rebuild` for the lists, `ocsp_expiry` for the responder |
| `tidy` | drops expired certificates and revocations |

Serial numbers are 128 random bits, reported as colon separated uppercase hex
and accepted with or without the colons, in either case.

The reason of a revocation is part of the record, not a comment on it: it is
reported by `cert/:serial`, carried by the entry of the list, and repeated by
the responder, so a client can tell a key compromise from a certificate that
was simply superseded. The certificate itself is accepted as well, so a caller
that holds the PEM does not have to read the serial out of it. The codes are
the ones of RFC 5280 — 0, 1, 2, 3, 4, 5, 6, 8, 9 and 10 — and 7, which was
never assigned, is refused. Revoking twice answers the first revocation with
its original time and reason, and warns.

The CRL is cached as DER in storage, because an SM2 signature is randomised: a
CRL rebuilt on every read would carry a different signature each time and no
client could cache it. Writing a revocation marks the cache dirty and the next
read rebuilds it, so `revoke` alone never pays for a signature nobody asked for.
`crl/rotate` forces a rebuild. `config/crl` sets how long a list claims to be
current, and `auto_rebuild=false` there stops a read from signing at all: the
rotate paths then become the only way a list changes.

A list names the certificates a client may still be shown, so one that has
passed its expiration is left out of it the next time the list is signed. That
is what keeps the list itself from growing: it carries the revocations of the
certificates that are still live, not a history. The records behind the entries
are kept, so `cert/:serial`, `certs/revoked` and the responder keep answering
for a serial after its entry has left the list.

A mount that has rotated holds more than one authority, and `crl` answers for
the one it signs with. Each authority keeps a list of its own, and
`issuer/:ref/crl` reads it, so a certificate signed before the rotation is
checked against a list its own authority signed. Point `crl_distribution_points`
at that form and update it after a rotation:

```bash
vault write pki-gmsm/config/urls \
    crl_distribution_points="$VAULT_ADDR/v1/pki-gmsm/issuer/$ISSUER_ID/crl"
```

A certificate keeps naming the address that was current when it was signed, and
that address keeps answering for as long as the mount holds the authority.
Retiring the authority is what takes its list away, which is why that is refused
while its certificates are still valid.

A mount written before every certificate recorded the authority that signed it
holds records that name none. They belong to the authority that was signing when
they were written, and the mount remembers which one that was the first time it
points at another: a rotation does not hand them to the authority that takes
over. The revocation of such a certificate still reaches the list its client
downloads, and that authority is not retired while those certificates are in
use.

`tidy` runs synchronously and answers with what it removed. It takes
`safety_buffer` (72h), `tidy_cert_store` (off) and `tidy_revoked_certs` (on).
The list stops carrying an expired certificate on its own, but the records of
the certificates and of the revocations stay until tidy says they may go, so
schedule it rather than calling it by hand: nightly is enough for a mount that
issues every day, and weekly for one whose certificates live for weeks. A mount
that is never tidied keeps every certificate it ever issued.

### Delta CRLs

A full list grows with every revocation, and a client that already holds it
should not download it again to learn one serial. `crl/delta` answers with the
changes since the full list it names, in the same three forms as `crl`. The
JSON form reports `base_number` beside `number`, `this_update` and
`next_update`.

The list names its base in the delta CRL indicator extension, which is marked
critical, so a client that cannot read it does not take the delta for a
complete list. Its own number follows the number of that base, which is what
lets the two be compared, and it is signed by the same authority and cached as
DER the same way. On a rotated mount, `issuer/:ref/crl/delta` is the delta of
the list that authority publishes, numbered on its own like that list.

A delta is signed on read when it is missing, when it has gone stale, when a
revocation has outdated it, or when the full list it names is no longer the one
being served. The last case is why the extension exists: a delta applied to the
wrong list revokes serials a client never saw revoked, and misses others.

By default a read rebuilds the full list after a revocation as well, which
keeps a client current but leaves the delta little to carry. A deployment that
saves bandwidth schedules the full list instead: turn `auto_rebuild` off in
`config/crl`, call `crl/rotate` when the full list should move, and read
`crl/delta` or call `crl/rotate-delta` in between. A client then downloads the
full list on the schedule and the changes in between. A full list that has
expired is signed again even then, because a client may not apply a delta to a
list it can no longer use.

Two things a client has to live with. Successive deltas repeat what the full
list still lacks, so an entry may appear in more than one and applying it twice
means the same as once. And no list says that a revocation was taken back: a
list stops naming a certificate once it has expired, and by then a client has
stopped accepting it, so `removeFromCRL` is never written.

## The responder (OCSP)

`ocsp` answers RFC 6960 status queries about the certificates the mount issued,
and the answer is signed by the authority that signed the certificate. A client
asks about one certificate at a time:

```bash
# The DER request travels base64-encoded, in a field of a write...
curl -s -o answer.der --data-binary "{\"request\": \"$REQUEST\"}" \
  https://vault.example.com/v1/pki-gmsm/ocsp

# ...or in the path of a read.
curl -s -o answer.der https://vault.example.com/v1/pki-gmsm/ocsp/$REQUEST
```

The body is `application/ocsp-response`, and the answer is `good`, `revoked` or
`unknown`. A request that cannot be answered is answered in the protocol as
well — `malformedRequest`, `internalError` or `unauthorized`, over HTTP 400, 500
or 401 — so that a client can tell a responder which refused from one that is
not there. `ocsp` and `ocsp/*` are unauthenticated, because a client that checks
a certificate holds no token of this Vault; that is the point of the endpoint.

The encoding is required, and this is the one place where a plugin cannot follow
the protocol literally. RFC 6960 also allows the request to be the body of the
POST, and Vault reads that form for the responder it builds in, but a plugin is
handed the data of a request and not the HTTP request, so a DER body never
reaches it. The base64 form is what a plugin can receive: a stock OCSP client
that posts DER to the address in `ocsp_servers` needs a responder inside Vault,
or a shim that encodes the request first.

Only the first request of a message is answered, and a message that names more
than one certificate is refused rather than half answered. The digests a request
may name are SHA-1, SHA-256, SHA-384, SHA-512 and SM3, which is the one a client
of an SM2 authority uses.

The status comes from what the mount recorded. A serial it never issued is
`unknown`. After a rotation, a certificate of the authority that signed it stays
`good` or `revoked`, while it is `unknown` under the authority that replaced it,
and a revocation recorded against one authority never travels to the other. The
answer names the authority itself as the responder, so the certificate that
issued a certificate is what checks its answer. An answer that reports a
revocation carries the time of it and the reason it was recorded with.

How long an answer stays current is set by `config/crl`: `ocsp_expiry` is
twelve hours unless it is written, and 0 leaves the next update out, which
tells a client that a fresher answer is available at any time. The same call
sets `expiry` for the lists, 72 hours unless it is written, where 0 restores
that default.

The address a certificate publishes is the one written in `config/urls`:

```bash
vault write pki-gmsm/config/urls ocsp_servers=https://vault.example.com/v1/pki-gmsm/ocsp
```

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

The request can also write the constraint the intermediate carries:
`permitted_dns_domains` and `excluded_dns_domains` take DNS names, where an
entry starting with a dot covers the subdomains below it as well, and
`permitted_ip_addresses` and `excluded_ip_addresses` take CIDR blocks. A bare
address is refused rather than read as a single host, because the two mean
different things. The extension is critical whenever one of them is written,
so a client that cannot check a constraint does not accept what is below it.

## Differences from Vault pki

| | Vault pki | This plugin |
| --- | --- | --- |
| Key algorithm | RSA, ECDSA, Ed25519 | SM2 only |
| Certificate signature | SHA-2 family | `SM2WithSM3` only |
| Subject key identifier | SHA-1 of the public key, RFC 5280 method 1 | SM3 of the public key, truncated to 160 bits |
| Issuers | Many, addressed by name or identifier, with rotation and cross-signing | Many, addressed by identifier or name, with rotation; no cross-signing |
| Changing an authority | `POST issuer/:ref` sets its name, its `usage` (`issuing-certificates`, `crl-signing`, `ocsp-signing`, `read-only`), `leaf_not_after_behavior`, `manual_chain`, `revocation_signature_algorithm` and its own AIA and CRL URLs | The same write, with `issuer_name`, `usage`, `leaf_not_after_behavior` and its own AIA, CRL and OCSP addresses; `manual_chain` and `revocation_signature_algorithm` are not there |
| Naming the authority that signs | In the path, on `issuer/:ref/issue`, `/sign`, `/sign-intermediate`, `/sign-self-issued` and `/sign-verbatim`, or through `role.issuer_ref` | In the path on `issuer/:ref/issue/:role` and `/sign/:role`, or through `role.issuer_ref`; the path wins over the role |
| Reading an authority | `issuer/:ref` as JSON, `issuer/:ref/pem` and `issuer/:ref/der` | The same three, and `ca` and `ca/pem` for the one in use; the JSON document carries the settings beside the certificate |
| Importing an authority | `config/ca`, `issuers/import/bundle` | `config/ca`, as the first authority of a mount |
| Certificate profile | Role fields `not_after`, `policy_identifiers`, `allowed_other_sans`, `allowed_serial_numbers`, `allowed_user_ids`, `csr_extra_names_oids` and `basic_constraints_valid_for_non_ca` | `not_after`, `policy_identifiers` and `allowed_other_sans`; the subject serial number, the user id and the extra names of a request are not there, and the basic constraints are always marked valid |
| A signed intermediate | Name constraints (`permitted_dns_domains`, `excluded_dns_domains`, `permitted_ip_addresses`, `excluded_ip_addresses`), `key_usage`, `not_before_duration` and `enforce_leaf_not_after_behavior` | `csr`, `common_name`, `use_csr_values`, `ttl`, `max_path_length`, the four name constraints and `format` |
| Revoking | `revoke` by serial or by PEM, with a `revocation_reason`; `revoke-with-key` takes the private key instead; `LIST certs/revoked` reports what was revoked | By serial or by PEM, with the reason codes RFC 5280 defines; `revoke-with-key` is not there, and `LIST certs/revoked` reports what the mount revoked |
| CRL and OCSP lifetime | `config/crl` sets `expiry`, `ocsp_expiry`, `disable`, `ocsp_disable`, `auto_rebuild` and `max_crl_entries` | The same call sets `expiry`, `ocsp_expiry` and `auto_rebuild`; there is no way to turn a list or the responder off, and no cap on the entries of a list |
| Delta CRLs | `crl/delta`, `/delta/pem`, `/delta/der`, `issuer/:ref/crl/delta` and `crl/rotate-delta`, behind `enable_delta` | The same paths, without the switch: a delta is built whenever one is asked for |
| A list built elsewhere | `issuer/:ref/sign-revocation-list` signs a supplied list of entries; `issuer/:ref/resign-crls` combines lists | Not implemented |
| URLs in a certificate | `config/urls` with `{{issuer_id}}` and `{{cluster_aia_path}}`, per-authority overrides, delta CRL points, and `config/cluster` for the address of the cluster | Three static lists on the mount, each overridable on one authority; no templating, no delta points and no cluster address |
| CA key | `keys`, `key/:ref`, `config/keys`, a root-only `keys/:ref/export`, and the `kms` key type, which needs managed keys | The key of an authority is held by a signer provider the plugin is built with, or is imported with `config/ca`; there is no key store of its own, no export path and no managed keys |
| Lease | Optional per-certificate lease | Not implemented; `generate_lease` only produces a warning |
| `no_store` | The certificate is kept nowhere and cannot be revoked by serial | The metadata is kept, so the serial stays revocable |
| Reading a stored certificate | `cert/:serial`, `cert/:serial/raw`, `/raw/pem` and `cert-metadata/:serial` | `cert/:serial`, which carries the PEM |
| Tidy | Asynchronous, with `tidy/:type/status`, `tidy-cancel` and `config/auto-tidy` | Synchronous, and it answers with what it removed |
| Deleting the authority | `DELETE root` needs a root token | Any token whose policy allows writing `root`, and only once one authority is left on the mount |
| Enrollment protocols | ACME in the open-source engine; EST, CMPv2 and SCEP only in Vault Enterprise | None |
| CRL | Rebuilt on demand, cached in memory | Cached as DER in storage, because the signature is randomised |
| OCSP | `ocsp_enable` and a responder that reads the DER body | A responder that reads the request base64-encoded, because a plugin never sees the body |

Unified CRLs and OCSP, the external policy service and managed keys are Vault
Enterprise features; the table compares this plugin with the open-source engine.
Where a path or a field exists in both, it behaves as it does in pki and keeps
the name pki gives it — the rows above are what is absent or different, not what
is renamed.
