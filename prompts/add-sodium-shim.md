# Add libsodium-wrappers-sumo drop-in shim

Export a secondary entry point that acts as a drop-in replacement for `libsodium-wrappers-sumo`. This lets any project that depends on libsodium through transitive dependencies (like `@cardano-sdk/crypto` via Lucid) alias the import to this shim and eliminate the 40MB WASM dependency.

## Entry point

```
noble-bip32ed25519/sodium
```

Consumers use it via esbuild alias, webpack alias, or package.json imports map:
```bash
# esbuild
--alias:libsodium-wrappers-sumo=noble-bip32ed25519/sodium
```

## Functions to implement

These are the 12 functions `@cardano-sdk/crypto` actually calls. No other libsodium consumer in the Cardano JS ecosystem uses functions outside this set.

| Function | Implementation |
|----------|---------------|
| `ready` | `Promise.resolve()` — noble is synchronous |
| `crypto_auth_hmacsha512(msg, key)` | `hmac(sha512, key, msg)` |
| `crypto_hash_sha512(msg)` | `sha512(msg)` |
| `crypto_generichash(len, msg)` | `blake2b(msg, { dkLen: len })` |
| `crypto_scalarmult_ed25519_base_noclamp(scalar)` | `ExtendedPoint.BASE.multiply(scalar % L).toRawBytes()` |
| `crypto_core_ed25519_add(p, q)` | `ExtendedPoint.fromHex(p).add(ExtendedPoint.fromHex(q)).toRawBytes()` |
| `crypto_core_ed25519_scalar_add(x, y)` | `(x + y) % L` as little-endian bytes |
| `crypto_core_ed25519_scalar_mul(x, y)` | `(x * y) % L` as little-endian bytes |
| `crypto_core_ed25519_scalar_reduce(s)` | `s % L` (64-byte input → 32-byte output) |
| `crypto_sign_detached(msg, sk)` | `ed25519.sign(msg, sk.slice(0, 32))` |
| `crypto_sign_seed_keypair(seed)` | `{ publicKey: ed25519.getPublicKey(seed), privateKey: [seed \| pubkey] }` |
| `crypto_sign_verify_detached(sig, msg, pk)` | `ed25519.verify(sig, msg, pk)` |

## Implementation notes

- The core already has `bytesToBigInt`, `bigIntToBytes`, and the curve order `L` — reuse them
- Default export must be an object with all 12 properties (matches `import sodium from 'libsodium-wrappers-sumo'`)
- `crypto_generichash` sometimes receives a key parameter (optional) — blake2b supports this via `{ key }` option
- Scalar inputs are little-endian Uint8Arrays
- `crypto_sign_detached` with a 64-byte secret key: first 32 bytes are the seed, last 32 are the public key (NaCl convention)

## package.json exports

Add to the existing exports map:

```json
{
  "exports": {
    ".": "./dist/index.js",
    "./compat": "./dist/compat.js",
    "./sodium": "./dist/sodium-shim.js"
  }
}
```

## Tests

Test against actual `libsodium-wrappers-sumo` output for the same inputs — every function must produce byte-identical results. Use the test vectors from the core library's BIP32 derivation tests as inputs.
