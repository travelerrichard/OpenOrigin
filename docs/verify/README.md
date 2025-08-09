# OpenOrigin / ProofPost – How to Verify Packages

This repository includes a **Download & Verify** page you can host anywhere. It performs all checks **locally in the browser** (no uploads).

## How to Verify
1) Open `docs/verify/index.html` in a modern browser (or host it as a static page).
2) Select the `*_package.zip` you downloaded.
3) (Optional) Provide the `.sig` file and a public key to verify signatures.
4) (Optional) Paste an expected package SHA-256 from a transparency log.
5) Read the results: structure, hashes, signature, and expected-hash checks.

> Privacy note: verification and hashing occur entirely on your device via WebCrypto. Nothing is transmitted.
