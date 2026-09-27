# SENTINEL — SIH26237 Vercel Ready

Cryptographic Attribution and Immutable Decryption Provenance for Multi-Recipient Encrypted Document Distribution.

## Stack
- Vercel Node.js 24 Function
- Express 5 + Multer
- PDF-Lib
- Native Node crypto
- ML-KEM-768 (NIST FIPS 203)
- ML-DSA-65 (NIST FIPS 204)
- AES-256-GCM
- SHA-256 hash-linked append-only ledger
- No SQL/NoSQL database
- No cloud KMS
- No public blockchain

## Vercel storage model
Vercel Functions provide a read-only filesystem plus writable `/tmp` scratch space. SENTINEL stores runtime state in `/tmp/sentinel-runtime` only. That means the demo is intentionally ephemeral: a cold start, instance replacement, or scale-out can reset local state. This satisfies the requested temporary-storage/no-database design, but it is NOT a durable multi-node ledger.

For the SIH demo, keep one active instance/session where possible. For a real defence deployment, replace the `/tmp` repository with an offline replicated DLT node layer or a controlled persistent storage layer while keeping the same application API.

## Deploy from GitHub
1. Push this entire folder to a GitHub repository.
2. Import the repository into Vercel.
3. Framework Preset: Other.
4. Build Command: leave empty.
5. Output Directory: leave empty.
6. Deploy.

Vercel detects `vercel.json` and deploys `api/index.js` as the Node.js function.

## Local
Requires Node 24.7+ because Node's native ML-KEM and ML-DSA APIs were added in Node 24.7 and 24.6 respectively.

```bash
npm install
npx vercel dev
```

Then open the URL printed by Vercel.

## Demo workflow
1. Dashboard → inspect CIA/security state.
2. Documents → upload a PDF.
3. Recipients → create or use sample recipient.
4. Decryption → Distribute → Decrypt → Fingerprint → Sign → Ledger.
5. Download the fingerprinted PDF.
6. Forensics → upload that PDF.
7. Extract the watermark, match the ledger event, and verify the ML-DSA signature.

## Security note
The PDF fingerprint is an SIH demonstration mechanism. It is not a claim that the fingerprint survives every screenshot, print, OCR, re-render, or hostile document transformation. A production deployment should add a robust redundant DCT/DWT watermark plus error-correcting codes and a multi-node quorum ledger.
