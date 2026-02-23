# Quantum Signer
## Digital signature tool

Static client-only web app for post-quantum detached signatures (`.qsig`) using pure HTML/CSS/JS.

[Features](#features) | [Architecture](#architecture) | [Development](#development) | [License](#license)

------------

## Features

1. Key management: generate/import/export key pairs for ML-DSA and SLH-DSA.
2. Sign: select a file, create detached signature, download `.qsig`.
3. Verify: select original file + `.qsig`, get `VALID`/`INVALID` with technical details.

------------

## Architecture

### Algorithms and standards alignment

Supported suites:
- ML-DSA-44 / 65 / 87 (FIPS 204 family)
- SLH-DSA-SHAKE-128s / 192s / 256s (FIPS 205 family)

Hashing:
- SHA3-512 prehash (FIPS 202) for file digest inside signed TBS payload.

Important note:
- This project follows the algorithm specifications and good implementation practices, but it is not a formally FIPS-validated module.

### Security model

- `no network`: no runtime fetch/XHR/WebSocket/analytics/CDN.
- `offline-first`: app works from static files and can be used offline.
- `keys stay in browser`: keys are memory-resident in session; no server round-trips.
- Key/signature lengths are validated against selected suite before signing/verifying.
- Detached signature format is versioned and parsed defensively.

### Detached signature format (`.qsig`)

Container includes:
- `magic` + `version`
- `suite id` (ML-DSA / SLH-DSA parameter set)
- `hash id` (`SHA3-512`)
- `file hash` (prehash)
- optional metadata (`filename`, `filesize`, `createdAt` ISO8601)
- signer key data:
  - optional embedded public key
  - mandatory signer fingerprint record (`SHA3-256(pubkey)`)
- signature bytes (detached)

Verification UI shows:
- algorithm,
- hash used,
- signer fingerprint,
- signature size,
- computed vs signed hash.

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
- malformed container parse rejection

Full mode (extra SLH suites):

```bash
FULL_SELFTEST=1 npm run selftest
```

### Build

```bash
npm run build
```

### GitHub Pages deploy

Push to `main` triggers `.github/workflows/pages.yml`, which:
- installs dependencies,
- runs self-tests,
- builds static app into `dist/`,
- publishes `dist/` via GitHub Pages.

------------

## License

This project is distributed under the terms of the GNU Affero General Public License v3.0. See the `LICENSE` file for the full text.

### Third‑party software licensed under other licenses

Browser crypto tool libraries:
* SHA3-512 and SHA2-512 for hashing [noble-hashes](https://github.com/paulmillr/noble-hashes);
* ML-DSA and SLH-DSA for post-quantum digital signature algorithms [noble-post-quantum](https://github.com/paulmillr/noble-post-quantum);

The application incorporates the following dependencies that are released under the permissive MIT License.

| Library               | Version | Copyright holder | Upstream repository                               |
| --------------------- | ------- | ---------------- | ------------------------------------------------- |
| noble-post-quantum    | 0.5.4   | Paul Miller      | https://github.com/paulmillr/noble-post-quantum   |
| noble-hashes          | 2.0.1   | Paul Miller      | https://github.com/paulmillr/noble-hashes         |
