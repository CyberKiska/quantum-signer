# Release verification

Quantum Signer 2.0.1 provides local signing through Node.js 26+ and a verification-only browser application. The native CLI supports all six QSIG suites. Browser private-key operations are unavailable.

## Authenticate before executing

Download artifacts from the successful `release.yml` workflow for the approved commit on `main`. A local build is not automatically an authenticated published release.

Using a separately installed, trusted GitHub CLI:

```sh
gh attestation verify release/release-manifest.json \
  -R CyberKiska/quantum-signer \
  --signer-workflow CyberKiska/quantum-signer/.github/workflows/release.yml \
  --source-ref refs/heads/main \
  --source-digest REVIEWED_COMMIT \
  --deny-self-hosted-runners
```

Replace `REVIEWED_COMMIT` with the full release commit identifier obtained through a trusted channel. Require the expected repository, workflow, branch and commit. A missing or unsuccessful attestation is a failed origin check.

From a separately trusted source checkout, check the downloaded inventory:

```sh
node scripts/verify-release.mjs /absolute/path/to/release
```

This rejects altered, missing, additional and symlinked files. It does not authenticate the manifest by itself. Verify provenance first; never execute a downloaded CLI to decide whether that same CLI is trustworthy.

For offline distribution, preserve the verified artifacts and use [GitHub CLI offline attestation verification](https://cli.github.com/manual/gh_attestation_verify) with an independently obtained trusted root and attestation bundle.

## Run the authenticated CLI

```sh
node release/quantum-signer.mjs doctor
node release/quantum-signer.mjs keygen --secret signer.pqse --public signer.pqpk
node release/quantum-signer.mjs hash --file document.bin
node release/quantum-signer.mjs sign --secret signer.pqse --file document.bin --expect-sha3-512 REVIEWED_DIGEST --out document.qsig
node release/quantum-signer.mjs verify --file document.bin --signature document.qsig --public signer.pqpk
```

Replace `REVIEWED_DIGEST` with the exact SHA3-512 digest you reviewed. New keys are encrypted PQSE 2 files containing PKCS#8. Legacy PQSE 1 and PQSK keys remain importable. Existing QSIG 2 signatures remain compatible. Share public keys and signatures, never private keys or passphrases.

Verification exits 0 for validity with a matching selected public key, 2 for valid signatures using only the embedded key, and 1 for errors or invalid signatures. Independently authenticate the selected public key or its full fingerprint.

Use a private output directory and secure backups. Native KeyObjects do not guarantee hardware isolation or erasure of passwords and OS/runtime memory copies. Node/OpenSSL use and a reported FIPS-mode flag are not module certification claims.

## Build and validate from source

```sh
npm ci
FULL_SELFTEST=1 npm run check
npm run test:external-vectors
npm audit --audit-level=high
npm run check:repro
BASE_PATH=/quantum-signer/ npm run check:repro
npm run test:release
```

`test:release` creates the `release/` directory, verifies repeat-build equality, checks the standalone CLI, and exercises inventory tampering. No signing secrets or internal audit documents belong in the public source or release artifact.

The release workflow runs the checks before producing artifacts. Its separate attestation job does not execute project dependencies. Protect `main` and workflow changes, require the CI checks, and distribute artifacts from the exact approved commit. For future releases, review changes before updating pinned build digests.

## Browser deployment

The `browser/` directory contains the static application. Serve it on a dedicated HTTPS origin and apply its `_headers` policy on a compatible host. Verify actual response headers and SRI after deployment. The worker is embedded in the SRI-covered app asset; unsigned hashes and SRI do not authenticate the HTML origin itself.

GitHub Pages remains a header-limited verification demo. An origin compromise can falsify displayed verification results. Use an authenticated local release where delivery assurance is required.
