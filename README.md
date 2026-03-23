# noble-bip32ed25519

Pure TypeScript BIP32-Ed25519 key derivation built on [`@noble/curves`](https://github.com/paulmillr/noble-curves) and [`@noble/hashes`](https://github.com/paulmillr/noble-hashes). Drop-in replacement for `@stricahq/bip32ed25519` without the ~40MB `libsodium-wrappers-sumo` dependency.

**4.5KB** compressed. No WASM, no native bindings, no async init. Just math.

## Install

```bash
npm install noble-bip32ed25519
```

## Usage

```typescript
import { Bip32PrivateKey } from 'noble-bip32ed25519';

// Entropy from BIP39 mnemonic (16-32 bytes)
const root = Bip32PrivateKey.fromEntropy(entropy);

// CIP-1852 derivation: m/1852'/1815'/0'/0/0
const paymentKey = root
  .derive(0x80000000 + 1852)
  .derive(0x80000000 + 1815)
  .derive(0x80000000)
  .derive(0)
  .derive(0);

// Sign
const privateKey = paymentKey.toPrivateKey();
const signature = privateKey.sign(message);

// Verify
const publicKey = privateKey.toPublicKey();
publicKey.verify(message, signature); // true

// Address construction
const keyHash = publicKey.hash(); // blake2b-224, 28 bytes
```

## API

### `Bip32PrivateKey`

| Method | Returns | Description |
|---|---|---|
| `static fromEntropy(entropy: Uint8Array)` | `Bip32PrivateKey` | Root key from BIP39 entropy (PBKDF2-HMAC-SHA512, Icarus scheme) |
| `derive(index: number)` | `Bip32PrivateKey` | Hardened if `index >= 0x80000000`, soft otherwise |
| `toPrivateKey()` | `PrivateKey` | Extract signing key |
| `toBip32PublicKey()` | `Bip32PublicKey` | For public-only (watch-only) derivation |

### `Bip32PublicKey`

| Method | Returns | Description |
|---|---|---|
| `derive(index: number)` | `Bip32PublicKey` | Soft derivation only (throws on hardened) |
| `toPublicKey()` | `PublicKey` | Extract public key |

### `PrivateKey`

| Method | Returns | Description |
|---|---|---|
| `sign(message: Uint8Array)` | `Uint8Array` | Ed25519 signature (64 bytes) |
| `toPublicKey()` | `PublicKey` | Derive public key |
| `toBytes()` | `Uint8Array` | Raw key bytes (64 bytes: kL \|\| kR) |

### `PublicKey`

| Method | Returns | Description |
|---|---|---|
| `verify(message: Uint8Array, signature: Uint8Array)` | `boolean` | Ed25519 verification |
| `toBytes()` | `Uint8Array` | Raw public key (32 bytes) |
| `hash()` | `Uint8Array` | blake2b-224 hash (28 bytes) |

All methods are **synchronous**. All byte values are **`Uint8Array`**.

## Migrating from @stricahq/bip32ed25519

The API shape is nearly identical. The main differences: `fromEntropy()` is synchronous (no `await`), all byte types are `Uint8Array` instead of `Buffer` (use `Uint8Array.from(buffer)` / `Buffer.from(uint8array)` at boundaries if needed), and `toPublicKey()` on `Bip32PrivateKey` is replaced by `toBip32PublicKey()` which returns a `Bip32PublicKey` capable of soft derivation — call `.toPublicKey()` on that if you just need the raw public key. The derivation paths, key bytes, signatures, and hashes are byte-identical to the libsodium-based implementation.

## How it works

`@stricahq/bip32ed25519` uses three libsodium functions. This library replaces them with `@noble/curves` equivalents:

| libsodium | noble |
|---|---|
| `crypto_scalarmult_ed25519_base_noclamp` | `ExtendedPoint.BASE.multiply(scalar)` |
| `crypto_core_ed25519_scalar_add` | 256-bit little-endian integer addition |
| `crypto_core_ed25519_add` | `point1.add(point2)` |

The test suite includes cross-library verification against `@stricahq/bip32ed25519` to ensure byte-identical output for root keys, derived payment/stake keys, public key hashes, and signatures.

## Contributing

Contributions, forks, and issues are welcome. This is a small, focused library — the entire implementation is ~340 lines across two files (`src/crypto.ts` and `src/index.ts`).

## License

MIT
