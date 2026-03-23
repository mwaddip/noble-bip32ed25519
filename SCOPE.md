# noble-bip32ed25519

Pure TypeScript BIP32-Ed25519 key derivation built on `@noble/curves` and `@noble/hashes`. Zero WASM, zero libsodium — just math.

## Problem

Every Cardano JS project depends on `@stricahq/bip32ed25519` → `libsodium-wrappers-sumo` (~40MB). libsodium is a C library compiled to JS/WASM that ships 300+ functions. Cardano key derivation uses three of them.

The `@noble/curves` library (audited, pure JS, widely used) already has the underlying Ed25519 primitives. Nobody has wired them up for BIP32-Ed25519 yet.

## What libsodium is actually used for

`@stricahq/bip32ed25519` calls three libsodium functions:

| libsodium function | Purpose | noble equivalent |
|---|---|---|
| `crypto_scalarmult_ed25519_base_noclamp` | Derive public key from private scalar | `ExtendedPoint.BASE.multiply(scalar)` |
| `crypto_core_ed25519_scalar_add` | Add two scalars mod L (child key derivation) | `(a + b) % CURVE_ORDER` — bigint arithmetic |
| `crypto_core_ed25519_add` | Add two Ed25519 points (soft derivation) | `point1.add(point2)` |

## Dependencies (already in Cardano projects)

- `@noble/curves` — Ed25519 curve operations (ExtendedPoint, scalar math)
- `@noble/hashes` — HMAC-SHA512, PBKDF2, SHA-512

No new dependencies. These are already in every Cardano JS project's tree via other packages.

## BIP32-Ed25519 derivation (Cardano Icarus scheme)

### Root key from mnemonic

1. Mnemonic → entropy (BIP39 standard)
2. Entropy → PBKDF2-HMAC-SHA512(password=entropy, salt="", iterations=4096, dkLen=96)
3. Result: 96 bytes = `[kL(32) | kR(32) | chainCode(32)]`
4. Clamp kL: `kL[0] &= 0xF8; kL[31] &= 0x1F; kL[31] |= 0x40`

### Hardened child derivation (index >= 0x80000000)

1. `Z = HMAC-SHA512(key=chainCode, data=0x00 || kL || kR || index_LE_32bit)`
2. `c = HMAC-SHA512(key=chainCode, data=0x01 || kL || kR || index_LE_32bit)`
3. `zL = Z[0..28]`, `zR = Z[32..64]`
4. `childKL = (8 * zL) + kL` (as 256-bit integers, mod 2^256)
5. `childKR = zR + kR mod 2^256`
6. `childChainCode = c[32..64]`

### Soft child derivation (index < 0x80000000)

1. `pubKey = kL * G` (Ed25519 base point multiplication)
2. `Z = HMAC-SHA512(key=chainCode, data=0x02 || pubKey || index_LE_32bit)`
3. `c = HMAC-SHA512(key=chainCode, data=0x03 || pubKey || index_LE_32bit)`
4. `zL = Z[0..28]`
5. `childKL = (8 * zL) + kL`
6. `childPubKey = (8 * zL) * G + pubKey` (point addition)
7. `childChainCode = c[32..64]`

### Cardano CIP-1852 derivation path

```
m / 1852' / 1815' / 0' / role / index
```

- Payment key: `m/1852'/1815'/0'/0/0` (3 hardened + 2 soft)
- Stake key: `m/1852'/1815'/0'/2/0` (3 hardened + 2 soft)

## API (drop-in for @stricahq/bip32ed25519)

```typescript
class Bip32PrivateKey {
  static fromEntropy(entropy: Buffer): Promise<Bip32PrivateKey>;
  derive(index: number): Bip32PrivateKey;        // hardened if >= 0x80000000
  toPrivateKey(): PrivateKey;
  toPublicKey(): PublicKey;                        // not available on Bip32PrivateKey directly — go through PrivateKey
}

class PrivateKey {
  toPublicKey(): PublicKey;
  sign(message: Buffer): Buffer;                  // Ed25519 signature
  toBytes(): Buffer;                               // 64 bytes (extended key)
}

class PublicKey {
  toBytes(): Buffer;                               // 32 bytes
  hash(): Buffer;                                  // blake2b-224 (28 bytes) — for Cardano address construction
  verify(message: Buffer, signature: Buffer): boolean;
}
```

## Test vectors

CIP-1852 provides test vectors for the standard derivation path. Additionally, verify against `@stricahq/bip32ed25519` output for the same mnemonic — the derived addresses must match.

Test mnemonic (standard 24-word): generate one, derive with both libraries, compare:
- Root key bytes (kL, kR, chainCode)
- Payment key at m/1852'/1815'/0'/0/0
- Stake key at m/1852'/1815'/0'/2/0
- Public key hashes (blake2b-224)
- Bech32 address

## Estimated size

~200-300 lines of TypeScript. No WASM, no native bindings. Bundles to <10KB.

## Who benefits

Every Cardano project using `@stricahq/bip32ed25519`, `cardano-serialization-lib`, or `@emurgo/cardano-serialization-lib` for key derivation. That's most of the ecosystem.

The `@noble/*` family is already the go-to for JS crypto. This fills a gap.
