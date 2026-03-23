import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { sha512 } from '@noble/hashes/sha512';
import { hmac } from '@noble/hashes/hmac';
import { blake2b } from '@noble/hashes/blake2b';
import { ed25519 } from '@noble/curves/ed25519';

const ExtendedPoint = ed25519.ExtendedPoint;

// Ed25519 group order
const L = 2n ** 252n + 27742317777372353535851937790883648493n;
const MOD_256 = 1n << 256n;
const VALID_ENTROPY_LENGTHS = [16, 20, 24, 28, 32];

export interface BIP32Key {
  kL: Uint8Array;
  kR: Uint8Array;
  chainCode: Uint8Array;
}

export interface BIP32PublicKey {
  pubKey: Uint8Array;
  chainCode: Uint8Array;
}

// --- Helpers (exported for sodium shim) ---

export { L, ExtendedPoint, sha512, hmac, blake2b, ed25519, concat };

export function bytesToScalar(bytes: Uint8Array): bigint {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    n = (n << 8n) | BigInt(bytes[i]);
  }
  return n;
}

export function scalarToBytes(n: bigint, length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    bytes[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return bytes;
}

function indexToLE32(index: number): Uint8Array {
  const buf = new Uint8Array(4);
  buf[0] = index & 0xff;
  buf[1] = (index >>> 8) & 0xff;
  buf[2] = (index >>> 16) & 0xff;
  buf[3] = (index >>> 24) & 0xff;
  return buf;
}

function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
}

function mod(n: bigint, m: bigint): bigint {
  return ((n % m) + m) % m;
}

// --- Exported functions ---

export function rootKeyFromEntropy(entropy: Uint8Array): BIP32Key {
  if (!VALID_ENTROPY_LENGTHS.includes(entropy.length)) {
    throw new Error(
      `Invalid entropy length: ${entropy.length}. Must be one of: ${VALID_ENTROPY_LENGTHS.join(', ')}`
    );
  }

  const raw = pbkdf2(sha512, new Uint8Array(0), entropy, {
    c: 4096,
    dkLen: 96,
  });

  const kL = raw.slice(0, 32);
  const kR = raw.slice(32, 64);
  const chainCode = raw.slice(64, 96);

  // Clamp kL
  kL[0] &= 0xf8;
  kL[31] &= 0x1f;
  kL[31] |= 0x40;

  return { kL, kR, chainCode };
}

export function publicKeyFromPrivate(kL: Uint8Array): Uint8Array {
  // Clamped kL can exceed curve order L (bit 254 set ≈ 2^254, L ≈ 2^252).
  // Reduce mod L before multiply() — mathematically equivalent since G has order L.
  const scalar = bytesToScalar(kL) % L;
  return ExtendedPoint.BASE.multiply(scalar).toRawBytes();
}

export function deriveChildHardened(key: BIP32Key, index: number): BIP32Key {
  const { kL, kR, chainCode } = key;
  const indexLE = indexToLE32(index);

  const Z = hmac(sha512, chainCode, concat(new Uint8Array([0x00]), kL, kR, indexLE));
  const c = hmac(sha512, chainCode, concat(new Uint8Array([0x01]), kL, kR, indexLE));

  const zL = Z.slice(0, 28);
  const zR = Z.slice(32, 64);

  // childKL = (8 * zL) + kL   (256-bit integer addition)
  const zLScalar = bytesToScalar(zL) * 8n;
  const kLScalar = bytesToScalar(kL);
  const childKLScalar = (zLScalar + kLScalar) % MOD_256;
  const childKL = scalarToBytes(childKLScalar, 32);

  // childKR = (zR + kR) mod 2^256
  const zRScalar = bytesToScalar(zR);
  const kRScalar = bytesToScalar(kR);
  const childKRScalar = (zRScalar + kRScalar) % MOD_256;
  const childKR = scalarToBytes(childKRScalar, 32);

  const childChainCode = c.slice(32, 64);

  return { kL: childKL, kR: childKR, chainCode: childChainCode };
}

export function deriveChildSoft(key: BIP32Key, index: number): BIP32Key {
  const { kL, kR, chainCode } = key;
  const pubKey = publicKeyFromPrivate(kL);
  const indexLE = indexToLE32(index);

  const Z = hmac(sha512, chainCode, concat(new Uint8Array([0x02]), pubKey, indexLE));
  const c = hmac(sha512, chainCode, concat(new Uint8Array([0x03]), pubKey, indexLE));

  const zL = Z.slice(0, 28);
  const zR = Z.slice(32, 64);

  // childKL = (8 * zL) + kL
  const zLScalar = bytesToScalar(zL) * 8n;
  const kLScalar = bytesToScalar(kL);
  const childKLScalar = (zLScalar + kLScalar) % MOD_256;
  const childKL = scalarToBytes(childKLScalar, 32);

  // childKR = (zR + kR) mod 2^256
  const zRScalar = bytesToScalar(zR);
  const kRScalar = bytesToScalar(kR);
  const childKRScalar = (zRScalar + kRScalar) % MOD_256;
  const childKR = scalarToBytes(childKRScalar, 32);

  const childChainCode = c.slice(32, 64);

  return { kL: childKL, kR: childKR, chainCode: childChainCode };
}

export function deriveChildSoftPublic(
  pubKey: Uint8Array,
  chainCode: Uint8Array,
  index: number
): BIP32PublicKey {
  const indexLE = indexToLE32(index);

  const Z = hmac(sha512, chainCode, concat(new Uint8Array([0x02]), pubKey, indexLE));
  const c = hmac(sha512, chainCode, concat(new Uint8Array([0x03]), pubKey, indexLE));

  const zL = Z.slice(0, 28);

  // childPubKey = (8 * zL) * G + pubKey
  const zLScalar = bytesToScalar(zL) * 8n;
  const zLPoint = ExtendedPoint.BASE.multiply(zLScalar);
  const parentPoint = ExtendedPoint.fromHex(pubKey);
  const childPoint = zLPoint.add(parentPoint);
  const childPubKey = childPoint.toRawBytes();

  const childChainCode = c.slice(32, 64);

  return { pubKey: childPubKey, chainCode: childChainCode };
}

export function sign(
  kL: Uint8Array,
  kR: Uint8Array,
  message: Uint8Array
): Uint8Array {
  const pubKey = publicKeyFromPrivate(kL);

  // nonce = SHA-512(kR || message)
  const nonceHash = sha512(concat(kR, message));
  const r = mod(bytesToScalar(nonceHash), L);

  // R = r * G
  const R = ExtendedPoint.BASE.multiply(r);
  const RBytes = R.toRawBytes();

  // hram = SHA-512(R || pubKey || message) mod L
  const hramHash = sha512(concat(RBytes, pubKey, message));
  const hram = mod(bytesToScalar(hramHash), L);

  // S = (r + hram * kL_scalar) mod L
  const kLScalar = bytesToScalar(kL);
  const S = mod(r + hram * kLScalar, L);
  const SBytes = scalarToBytes(S, 32);

  // signature = R || S
  return concat(RBytes, SBytes);
}

export function verify(
  pubKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array
): boolean {
  try {
    return ed25519.verify(signature, message, pubKey);
  } catch {
    return false;
  }
}

export function hashPublicKey(pubKey: Uint8Array): Uint8Array {
  return blake2b(pubKey, { dkLen: 28 });
}
