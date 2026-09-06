# Quantum Signer

Post-quantum detached signatures with a native Node/OpenSSL signing CLI and a verification-only browser application.

**Version: 2.0.1.** Signing runs locally through Node/OpenSSL; the browser is verification-only. The project does not claim FIPS module validation or independent security certification. See [release verification](docs/RELEASE.md) for authenticating downloaded artifacts.

## Signing locally

Use Node.js 26 or newer with ML-DSA and SLH-DSA support. From an authenticated source checkout:

```sh
node src/native/cli.mjs doctor
node src/native/cli.mjs keygen --secret signer.pqse --public signer.pqpk
node src/native/cli.mjs hash --file document.bin
node src/native/cli.mjs sign --secret signer.pqse --file document.bin --expect-sha3-512 REVIEWED_DIGEST --out document.qsig
node src/native/cli.mjs verify --file document.bin --signature document.qsig --public signer.pqpk
```

Replace `REVIEWED_DIGEST` with the exact SHA3-512 digest reviewed from the hash command. Passwords are prompted without echo. Automation can use `--passphrase-fd N`; never put passwords in command arguments. New passwords require at least 12 code points. Use a strong, unique password and secure backups.

New private keys are PKCS#8 encrypted inside PQSE 2 using PBKDF2-HMAC-SHA-512 (600,000 iterations) and AES-256-GCM. Older PQSE 1 and raw PQSK keys can be imported by the CLI. New key files require the new CLI; QSIG signature compatibility is preserved. Outputs are exclusive and mode 0600. Use a private output directory and appropriate Windows ACLs.

Use `--suite ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87` (default), `SLH-DSA-SHAKE-128s`, `SLH-DSA-SHAKE-192s`, or `SLH-DSA-SHAKE-256s` with `keygen`. Recover a public key with:

```sh
node src/native/cli.mjs public --secret signer.pqse --out signer.pqpk
```

The source CLI needs no third-party runtime cryptography. Signing, key generation, verification and SHA-3 use `node:crypto`; password protection uses standard Web Crypto. Private operations use native KeyObjects, pairwise key checks, and signature/container self-verification. There is no JavaScript signing fallback.

## Browser verification

```sh
npm ci
npm run preview
```

Open the displayed loopback address. Select a public `.pqpk` key from a trusted source, then the original file/text and `.qsig`. Browser key generation, private-key imports/exports and signing have been removed, including the worker handlers. The Sign tab explains local CLI use.

The browser runs public-only NIST known-answer tests at startup. Failure blocks worker operations. Worker bytes are embedded in the SRI-covered application bundle. Browser verification and hashing use pinned Noble libraries because complete native browser support for all suites is not uniform.

A matching loaded key gives `VALID`; an embedded key alone gives `UNTRUSTED`; a mismatched selected key or changed payload gives `INVALID`. CLI exit statuses are respectively 0, 2, and 1. A selected key is a trust input, not proof of its owner's identity: compare the full fingerprint through a trusted channel.

## Format and assurance

The [wire specification](spec/qsig-v2.txt) describes exact QSIG 2.0 bytes, authenticated metadata, contexts, reconstruction, legacy key files, PQSE 2, and applicable standards.

QSIG signs a structured 108-byte TBS containing SHA3-512 of the original payload and SHA3-256 of authenticated signer metadata, using the pure ML-DSA/SLH-DSA context API. It does not use KMAC/cSHAKE or the HashML-DSA/HashSLH-DSA variants. It is a custom protocol, not CMS, JOSE or COSE. Filename, timestamp and MIME type are not signed; nonempty display metadata is rejected. Text uses strict UTF-8 without Unicode or newline normalization.

Native KeyObjects reduce exposure of expanded private material to JavaScript. They do not provide hardware isolation, guaranteed erasure of passwords/runtime/OS copies, or protection from a compromised local machine. The legacy JavaScript signing/session modules remain only as regression references and are blocked from production bundles.

## Validation and release

```sh
npm run check
FULL_SELFTEST=1 npm run selftest
npm run test:external-vectors
npm run check:repro
BASE_PATH=/quantum-signer/ npm run check:repro
npm run test:release
```

CI runs full cryptographic checks on pull requests. Native/browser interoperability covers all six suites; external ML-DSA verification vectors run through both adapters. Container mutation, policy-injection, encrypted key, worker-fault and release-tampering checks are included.

The manual release workflow separates dependency-running builds from the job that attests the manifest. Authenticate provenance for the exact reviewed repository/workflow/ref/commit, then verify the full file inventory using a separately trusted checkout before running a downloaded artifact. Unsigned hashes and SRI alone do not authenticate an origin. See [release verification](docs/RELEASE.md) for commands and required operational controls.

`npm run package:release` creates `release/` with the standalone native CLI, browser build, licenses, specification and manifest. Run the authenticated standalone CLI as `node release/quantum-signer.mjs ...`.

GitHub Pages remains a manual, header-limited verification demo. Other static hosts should apply `dist/_headers` and validate the actual responses. Compromise of the HTML/origin can still falsify browser results; an authenticated local release is the stronger delivery model.

## License

GNU Affero General Public License v3.0 or later; see [LICENSE](LICENSE).

Browser cryptographic dependencies are [noble-hashes](https://github.com/paulmillr/noble-hashes) and [noble-post-quantum](https://github.com/paulmillr/noble-post-quantum), copyright Paul Miller, MIT licensed. Release artifacts include their license notices.
