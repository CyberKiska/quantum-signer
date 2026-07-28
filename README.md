# Quantum Signer

## Digital signature tool

Static client-only web app for post-quantum detached signatures (`.qsig`) using pure HTML/CSS/JS.

> **Security status:** experimental and not approved for high-assurance production signing.
> The pure-JavaScript ML-DSA/SLH-DSA engine is algorithm-compatible but not strictly
> FIPS-conformant, FIPS 140-3 validated, side-channel hardened, or backed by an application-visible
> approved RBG. Do not use long-lived or high-value private keys without resolving the blockers in
> [PRODUCTION-READINESS.md](./PRODUCTION-READINESS.md).

[Features](#features) | [Architecture](#architecture) | [Development](#development) |
[Production readiness](./PRODUCTION-READINESS.md) | [Security policy](./SECURITY.md) |
[QSIG v2 draft](./QSIG-V2.md) | [License](#license)

------------

## Features

1. Key management: generate/import/export key pairs for ML-DSA, SLH-DSA, and experimental Falcon.
2. Sign: select a file or text, review SHA3-512 payload digest and active signer, create detached signature, download `.qsig`.
3. Verify: review original input digest and declared `.qsig` metadata before verification; get
   `VALID`/`UNTRUSTED`/`INVALID` with separate primitive, signer-binding, and payload-match results.

Trust states are intentionally distinct: verification with a user-supplied public key may be shown as `VALID`; verification using only the key embedded in `.qsig` is shown as `UNTRUSTED` even when the cryptographic signature is internally consistent.
If loaded and embedded signer keys differ, container policy hard-fails even when a raw primitive
check succeeds with one of them.

------------

## Architecture

### Algorithms and standards alignment

Supported algorithm-compatible suites:

- ML-DSA-44 / 65 / 87 (FIPS 204 family; default pure-context profile)
- SLH-DSA-SHAKE-128s / 192s / 256s (FIPS 205 family; default pure-context profile)
- Falcon-512-padded / Falcon-1024-padded (experimental Falcon Round 3 support; not FN-DSA, not FIPS 206, and expected to be incompatible with final FN-DSA/FIPS 206)

Hashing:

- SHA3-512 payload digest (FIPS 202) for detached-content binding inside the current signed TBS payload.

Important limitations:

- The pinned pure-JavaScript PQ implementation uses ECMAScript `Number` arithmetic. Because
  FIPS 204 section 3.6.4 and FIPS 205 section 3.1 prohibit floating-point arithmetic, this is an
  algorithm-compatible integration, not a strict FIPS implementation-conformance claim.
- The pinned PQ package states that it is self-audited, not independently audited, and has no
  side-channel protection. Browser JIT, garbage collection, and hidden copies prevent reliable
  constant-time and zeroization guarantees.
- PQ key generation and hedged signing ultimately use `crypto.getRandomValues()`. The browser
  does not expose the SP 800-90A/B/C evidence needed for an approved-RBG or entropy-validation
  claim.
- QSIG v2 does not use KMAC or cSHAKE. KMAC has no legitimate role without a secret MAC key;
  cSHAKE remains a possible typed-hash choice for a future breaking format.
- `qsig v2` uses a project-specific detached-signature container around standard ML-DSA / SLH-DSA signing.
- `.qsig`, `.pqpk`, and `.pqsk` are custom encodings, not X.509, CMS, JOSE, or COSE. Relevant
  interoperability profiles include RFC 9814, RFC 9881, RFC 9882, RFC 9909, and RFC 9964, but
  their bytes and context rules must not be conflated with QSIG.
- ML-DSA and SLH-DSA domain separation is carried through the standardized algorithm `context` parameter, and signer metadata is authenticated explicitly.
- Falcon uses the `PQ_DETACHED_EXTERNAL_CONTEXT_V2` profile because the current noble Falcon API does not support the standardized `context` option. Quantum Signer signs `QSCX || wrapper-version || ctxLen || ctxBytes || TBS` for Falcon only. Treat this as an experimental interoperability boundary, not a NIST-standard Falcon/FN-DSA profile.

### Security model

- `no network`: no runtime fetch/XHR/WebSocket/analytics/CDN.
- `offline-capable`: after a reviewed build is available locally, the app needs no runtime network
  access. Browser behavior for direct `file:` module workers varies; localhost or a dedicated
  secure static origin is the supported execution model.
- `keys stay in browser`: public key data lives in UI session; private signing key bytes are isolated in a dedicated worker session with no server round-trips.
  This worker boundary is a defense against accidental UI-layer exposure and routine app bugs, not against same-origin code execution.
- `zero-trust delivery still applies`: if the page origin is compromised by XSS, an injected same-origin script, a malicious browser extension, or a tampered build, that code runs with the same origin privileges as the app and can still drive export flows or exfiltrate secrets.
- `deployment headers are required`: the hosting layer must serve CSP for both the document and worker, including `frame-ancestors 'none'` on the document response. The in-document CSP cannot enforce `frame-ancestors`; the runtime also refuses framed execution as defense in depth.
- `secure context is required`: startup fails outside a browser-designated secure context.
- `private key export is separately authorized`: exporting a private signing key now requires both the worker session handle and a per-session export consent token that is kept out of app state and issued only when the private-key session is created/imported.
- `private key files are raw secrets`: exported `.pqsk` files contain unencrypted private signing key material. The file CRC32 detects accidental corruption only; it does not provide confidentiality, authenticity, or tamper resistance. Store `.pqsk` files like any other signing secret.
- Key/signature lengths are validated against selected suite before signing/verifying.
- Browser-facing inputs are bounded by explicit policy limits for payloads, key files, signature containers, context, and metadata blocks.
- Detached signature format is versioned and parsed defensively.
- Signing holds a worker-side session lease and self-verifies every generated signature before any `.qsig` output is returned.
- Imported expanded private keys must pass a sign/verify pairwise-consistency test before a
  session or public key is exposed. ML-DSA and SLH-DSA use deterministic signing for this check;
  experimental Falcon uses its suite-default randomized signing behavior. This checks functional
  consistency, not provenance.
- Worker-held private-key sessions expire after 30 minutes without activity. Expiry denies new
  operations immediately and defers best-effort wiping only for an already-active lease.
- Sign and verify results are bound to immutable review snapshots; stale asynchronous completions are discarded.
- Text mode rejects unpaired UTF-16 surrogates. File mode should be used whenever exact source bytes and line endings matter.

### Detached signature format (`.qsig`)

Container includes:
- `magic` + `version`
- `suite id` (ML-DSA / SLH-DSA parameter set, or experimental Falcon parameter set)
- `signature profile id`
- `payload digest alg id` (`SHA3-512`)
- `payload digest`
- `auth metadata digest alg id`
- algorithm `context`
- authenticated signer metadata:
  - embedded public key
  - signer fingerprint record (`SHA3-256(pubkey)`)
- optional legacy display metadata (`filename`, `filesize`, `createdAt` UTC ISO8601 with
  millisecond precision); current producers omit it because it is unsigned
- signature bytes (detached)

Verification UI shows:

- algorithm,
- hash used,
- signer fingerprint,
- signature size,
- computed vs declared hash and whether that declared hash was signature-authenticated,
- trust caveat when verification succeeds only with embedded signer metadata,
- hard-failure diagnostics when loaded and embedded public keys disagree.

Scope boundaries:
- `.qsig` authenticates one exact payload byte string and the authenticated signer metadata defined by the format.
- It does not authenticate filesystem filename, MIME type, file/text mode, semantic schema, archive paths/order, or reconstruction rules.
- Display metadata is unauthenticated and MUST NOT be used for paths, policy, reconstruction, identity, or trust decisions.
- New Quantum Signer output emits an empty display-metadata block. The strict parser retains the
  fields only for existing/third-party v2 containers and the UI marks them unauthenticated.
- The v2 authenticated-metadata digest and signer fingerprint use SHA3-256, so their classical collision strength is capped at 128 bits. A future breaking format revision is required to raise this without changing v2 semantics.

The verifier evaluates the TBS signature even when the supplied payload digest differs. This
prevents attacker-controlled, unverified container fields from being presented as signed claims.

------------

## Development

### Install

```bash
npm ci
```

### Run locally

```bash
npm run dev
```

Open: `http://localhost:5173`

### Automated self-tests

```bash
npm run selftest
```

Covers:

- keygen -> sign -> verify (valid)
- verify on modified file (invalid)
- verify with wrong key (invalid)
- tampered signature (invalid)
- context mismatch (invalid)
- embedded-only verification semantics (`UNTRUSTED` presentation with a valid primitive check)
- loaded-vs-embedded mismatch hard failure
- signature evaluation on payload mismatch
- tampered authenticated metadata (parse rejection)
- wrong metadata-block namespace and future minor version rejection
- unknown critical authenticated metadata tag (parse rejection)
- unsupported signer fingerprint algorithm id (parse rejection)
- oversized context/signature/payload inputs (rejected)
- malformed verification lengths returning `false`
- private-key session lease and idle-expiry behavior
- malformed container parse rejection

Full mode (extra SLH suites and Falcon-1024):

```bash
FULL_SELFTEST=1 npm run selftest
```

### Build

```bash
npm run build
```

### Static-host security headers

`npm run build` emits `dist/_headers` for compatible static hosts. A production-like deployment
must verify the live document and worker response headers. GitHub Pages does not apply this file.

### GitHub Pages preview

`.github/workflows/pages.yml` is manual-only and requires an explicit public-preview
acknowledgement. It:

- installs dependencies,
- runs self-tests,
- builds static app into `dist/`,
- publishes `dist/` as a preview.

It is not a production deployment because GitHub Pages cannot enforce the generated CSP/security
headers.

------------

## License

This project is distributed under the terms of the GNU Affero General Public License v3.0. See the `LICENSE` file for the full text.

### Third‑party software licensed under other licenses

Browser crypto tool libraries (see their version in the package.json):
* SHA3-256 and SHA3-512 for hashing [noble-hashes](https://github.com/paulmillr/noble-hashes);
* ML-DSA and SLH-DSA for post-quantum digital signature algorithms [noble-post-quantum](https://github.com/paulmillr/noble-post-quantum);

The application incorporates the following dependencies that are released under the permissive MIT License.

| Library               | Copyright holder | Upstream repository                               |
| --------------------- | ---------------- | ------------------------------------------------- |
| noble-post-quantum    | Paul Miller      | https://github.com/paulmillr/noble-post-quantum   |
| noble-hashes          | Paul Miller      | https://github.com/paulmillr/noble-hashes         |
