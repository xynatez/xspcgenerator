# XSPC-256 Generator (Frontend Only)

A single-page app that implements the XSPC‑256 algorithm exactly as in the paper:

- Salt 16 bytes
- PBKDF2‑HMAC‑SHA256 with 100,000 iterations → 256‑bit key
- HMAC‑DRBG (SHA‑256) keystream for XOR pre/post processing
- AES‑GCM (IV 12 bytes, tag 128‑bit)
- Dummy byte insertion (ratio ≈ 0.15) at positions derived from a deterministic seed
- CRC32 integrity check over ciphertext before dummy insertion
- Packaging: `salt(16) | iv(12) | count(2) | positions(2×count) | crc32(4) | ciphertext+dummy`, then Base64URL

## Run locally

Web Crypto API needs a **secure context**:
- Serve via HTTPS, or
- Use `localhost`.

Quick dev server options:

```bash
# Python 3
python3 -m http.server 8000

# Node (if installed)
npx http-server -p 8000
```

Then open `http://localhost:8000/` and load `index.html` from this folder.

## Notes

- Decryption validates CRC32 before attempting AES‑GCM — corrupted blobs fail fast.
- Passphrase must match exactly.
- Dummy bytes are **not** stored; only their positions are stored. Values are random at encryption time.
