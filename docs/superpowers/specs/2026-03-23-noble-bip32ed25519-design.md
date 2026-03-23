# noble-bip32ed25519 Design Spec

Pure TypeScript BIP32-Ed25519 key derivation built on `@noble/curves` and `@noble/hashes`. Replaces the ~40MB `libsodium-wrappers-sumo` dependency with ~200-300 lines of auditable math.

## Goal

Eliminate the libsodium dependency from Cardano JS projects. The three libsodium functions used by `@stricahq/bip32ed25519` all have direct equivalents in `@noble/curves`:

| libsodium function | noble equivalent |
|---|---|
| `crypto_scalarmult_ed25519_base_noclamp` | `ExtendedPoint.BASE.multiply(scalar)` |
| `crypto_core_ed25519_scalar_add` | 256-bit little-endian integer addition (reduction mod L happens implicitly during point multiplication) |
| `crypto_core_ed25519_add` | `point1.add(point2)` |

## Architecture

Two layers, two source files:

### `src/crypto.ts` — Pure functions

All BIP32-Ed25519 math as pure functions (`Uint8Array` in, `Uint8Array` out):

- `rootKeyFromEntropy(entropy: Uint8Array): { kL, kR, chainCode }` — PBKDF2-HMAC-SHA512 (password=entropy, salt=empty, iterations=4096, dkLen=96), then clamp kL. Accepted entropy lengths: 16, 20, 24, 28, or 32 bytes (BIP39 128-256 bits)
- `deriveChildHardened(key, index)` — HMAC-SHA512 with `0x00 || kL || kR || index_LE`, scalar addition for child kL/kR
- `deriveChildSoft(key, index)` — HMAC-SHA512 with `0x02 || pubKey || index_LE`, scalar + point addition
- `deriveChildSoftPublic(pubKey, chainCode, index)` — Public-only soft derivation (point math only, no private key)
- `publicKeyFromPrivate(kL: Uint8Array): Uint8Array` — `ExtendedPoint.BASE.multiply(scalar).toRawBytes()`
- `sign(kL, kR, message): Uint8Array` — Ed25519 extended signing (see Signing Algorithm below)
- `verify(pubKey, message, signature): boolean` — Standard Ed25519 verification (can use `ed25519.verify()` from noble)
- `hashPublicKey(pubKey: Uint8Array): Uint8Array` — blake2b-224 (28 bytes)

**Clamping** (applied once to root kL):
```
kL[0]  &= 0xF8
kL[31] &= 0x1F
kL[31] |= 0x40
```

**Hardened child derivation** (index >= 0x80000000):
1. `Z = HMAC-SHA512(chainCode, 0x00 || kL || kR || index_LE_32bit)`
2. `c = HMAC-SHA512(chainCode, 0x01 || kL || kR || index_LE_32bit)`
3. `zL = Z[0..28]`, `zR = Z[32..64]`
4. `childKL = (8 * zL) + kL` (256-bit integer addition)
5. `childKR = (zR + kR) mod 2^256`
6. `childChainCode = c[32..64]`

**Soft child derivation** (index < 0x80000000):
1. `pubKey = kL * G`
2. `Z = HMAC-SHA512(chainCode, 0x02 || pubKey || index_LE_32bit)`
3. `c = HMAC-SHA512(chainCode, 0x03 || pubKey || index_LE_32bit)`
4. `zL = Z[0..28]`, `zR = Z[32..64]`
5. `childKL = (8 * zL) + kL` (256-bit integer addition)
6. `childKR = (zR + kR) mod 2^256`
7. `childPubKey = (8 * zL) * G + pubKey` (point addition)
8. `childChainCode = c[32..64]`

**Byte order:** All multi-byte integer arithmetic (scalar addition, multiplication by 8) uses little-endian byte order, matching Ed25519 convention.

**Signing algorithm** (Ed25519 extended, non-standard — cannot use noble's `ed25519.sign()`):

BIP32-Ed25519 uses a pre-clamped extended key (kL, kR) rather than a 32-byte seed. The nonce is derived from kR (not by hashing the seed). Steps:

1. `pubKey = kL * G` (derive public key from private scalar)
2. `nonce = SHA-512(kR || message)` (kR-based nonce, not seed-based)
3. `r = nonce mod L` (reduce to scalar, L = Ed25519 group order)
4. `R = r * G` (nonce point)
5. `hramDigest = SHA-512(R || pubKey || message)` (challenge)
6. `hram = hramDigest mod L`
7. `S = (r + hram * kL_scalar) mod L`
8. `signature = R_bytes || S_bytes` (64 bytes)

Verification is standard Ed25519 and can use `ed25519.verify()` from `@noble/curves`.

### `src/index.ts` — Public API

Thin class wrappers over the crypto functions. Hold state, delegate to `crypto.ts`.

```typescript
class Bip32PrivateKey {
  static fromEntropy(entropy: Uint8Array): Bip32PrivateKey  // synchronous
  derive(index: number): Bip32PrivateKey   // hardened if index >= 0x80000000
  toPrivateKey(): PrivateKey
  toBip32PublicKey(): Bip32PublicKey
}

class Bip32PublicKey {
  derive(index: number): Bip32PublicKey    // soft only, throws on hardened
  toPublicKey(): PublicKey
}

class PrivateKey {
  toPublicKey(): PublicKey
  sign(message: Uint8Array): Uint8Array    // 64-byte Ed25519 signature
  toBytes(): Uint8Array                     // 64 bytes (kL || kR)
}

class PublicKey {
  verify(message: Uint8Array, signature: Uint8Array): boolean
  toBytes(): Uint8Array                     // 32 bytes
  hash(): Uint8Array                        // 28 bytes, blake2b-224
}
```

Key design decisions:
- All `Uint8Array` (no Buffer dependency, browser-compatible)
- All synchronous (no libsodium async init)
- `Bip32PublicKey` enables watch-only wallet use cases

## Dependencies

### Runtime
- `@noble/curves` — Ed25519 ExtendedPoint, scalar math
- `@noble/hashes` — HMAC-SHA512, PBKDF2-SHA512, blake2b

### Dev-only
- `vitest` — test runner
- `typescript` — compilation
- `@stricahq/bip32ed25519` — cross-library test verification
- `bip39` — test mnemonic-to-entropy conversion

## Build

- ESM-only
- Target: ES2020 (BigInt support)
- Output: `dist/` with `.js` + `.d.ts`
- Package name: `noble-bip32ed25519`

## Testing

One test file: `test/derivation.test.ts`

### Tier 1: Cross-library verification
Derive keys with both `@stricahq/bip32ed25519` (libsodium) and our library from the same mnemonic. Assert identical:
- Root key bytes (kL, kR, chainCode)
- Payment key at `m/1852'/1815'/0'/0/0`
- Stake key at `m/1852'/1815'/0'/2/0`
- Public key bytes and blake2b-224 hashes
- Signatures on a test message

### Tier 2: Crypto unit tests
Test `crypto.ts` functions directly:
- PBKDF2 root key from known entropy
- Clamping bit manipulation
- Hardened/soft child derivation
- Scalar addition wrapping
- Point addition correctness

### Tier 3: Edge cases & errors
- `Bip32PublicKey.derive()` throws on hardened index
- Sign then verify round-trip
- Verify with wrong key/message fails
- Invalid entropy length rejected

## File structure

```
noble-bip32ed25519/
├── src/
│   ├── crypto.ts        # Pure derivation/signing functions
│   └── index.ts         # Public API classes
├── test/
│   └── derivation.test.ts
├── package.json
├── tsconfig.json
├── vitest.config.ts
└── SCOPE.md
```
