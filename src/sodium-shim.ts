import {
  L,
  ExtendedPoint,
  sha512,
  hmac,
  blake2b,
  ed25519,
  concat,
  bytesToScalar,
  scalarToBytes,
} from './crypto.js';

function crypto_auth_hmacsha512(
  message: Uint8Array,
  key: Uint8Array,
): Uint8Array {
  return hmac(sha512, key, message);
}

function crypto_hash_sha512(message: Uint8Array): Uint8Array {
  return sha512(message);
}

function crypto_generichash(
  hashLength: number,
  message: Uint8Array,
  key?: Uint8Array | null,
): Uint8Array {
  return blake2b(message, { dkLen: hashLength, key: key ?? undefined });
}

function crypto_scalarmult_ed25519_base_noclamp(
  scalar: Uint8Array,
): Uint8Array {
  // libsodium treats the scalar as a 255-bit little-endian integer
  // (it clears the top bit of byte 31 before scalar multiplication)
  const clamped = new Uint8Array(scalar);
  clamped[31] &= 0x7f;
  const s = bytesToScalar(clamped) % L;
  return ExtendedPoint.BASE.multiply(s).toRawBytes();
}

function crypto_core_ed25519_add(p: Uint8Array, q: Uint8Array): Uint8Array {
  return ExtendedPoint.fromHex(p).add(ExtendedPoint.fromHex(q)).toRawBytes();
}

function crypto_core_ed25519_scalar_add(
  x: Uint8Array,
  y: Uint8Array,
): Uint8Array {
  // libsodium's sc25519_add performs 256-bit addition (wrapping on overflow)
  // and then reduces mod L
  const MOD_256 = 1n << 256n;
  const sum = ((bytesToScalar(x) + bytesToScalar(y)) % MOD_256) % L;
  return scalarToBytes(sum, 32);
}

function crypto_core_ed25519_scalar_mul(
  x: Uint8Array,
  y: Uint8Array,
): Uint8Array {
  const product = (bytesToScalar(x) * bytesToScalar(y)) % L;
  return scalarToBytes(product, 32);
}

function crypto_core_ed25519_scalar_reduce(scalar: Uint8Array): Uint8Array {
  const reduced = bytesToScalar(scalar) % L;
  return scalarToBytes(reduced, 32);
}

function crypto_sign_detached(
  message: Uint8Array,
  secretKey: Uint8Array,
): Uint8Array {
  const seed = secretKey.slice(0, 32);
  return ed25519.sign(message, seed);
}

function crypto_sign_seed_keypair(seed: Uint8Array): {
  keyType: string;
  privateKey: Uint8Array;
  publicKey: Uint8Array;
} {
  const publicKey = ed25519.getPublicKey(seed);
  const privateKey = concat(seed, publicKey);
  return { keyType: 'ed25519', privateKey, publicKey };
}

function crypto_sign_verify_detached(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  try {
    return ed25519.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}

const sodium = {
  ready: Promise.resolve(),
  crypto_auth_hmacsha512,
  crypto_hash_sha512,
  crypto_generichash,
  crypto_scalarmult_ed25519_base_noclamp,
  crypto_core_ed25519_add,
  crypto_core_ed25519_scalar_add,
  crypto_core_ed25519_scalar_mul,
  crypto_core_ed25519_scalar_reduce,
  crypto_sign_detached,
  crypto_sign_seed_keypair,
  crypto_sign_verify_detached,
};

export default sodium;
