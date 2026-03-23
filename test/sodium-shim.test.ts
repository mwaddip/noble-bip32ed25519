import { describe, it, expect, beforeAll } from 'vitest';
import sodium from '../src/sodium-shim.js';
// @ts-expect-error — libsodium-wrappers-sumo has no types
import libsodium from 'libsodium-wrappers-sumo';

describe('sodium shim vs libsodium-wrappers-sumo', () => {
  beforeAll(async () => {
    await libsodium.ready;
    await sodium.ready;
  });

  const msg = new TextEncoder().encode('test message');
  const key32 = new Uint8Array(32).fill(0x42);
  const key64 = new Uint8Array(64).fill(0xab);

  // --- Hashing ---

  describe('crypto_auth_hmacsha512', () => {
    it('matches libsodium', () => {
      const ours = sodium.crypto_auth_hmacsha512(msg, key32);
      const theirs = libsodium.crypto_auth_hmacsha512(msg, key32);
      expect(ours).toEqual(new Uint8Array(theirs));
    });
  });

  describe('crypto_hash_sha512', () => {
    it('matches libsodium', () => {
      const ours = sodium.crypto_hash_sha512(msg);
      const theirs = libsodium.crypto_hash_sha512(msg);
      expect(ours).toEqual(new Uint8Array(theirs));
    });
  });

  describe('crypto_generichash', () => {
    it('matches libsodium without key', () => {
      const ours = sodium.crypto_generichash(32, msg);
      const theirs = libsodium.crypto_generichash(32, msg);
      expect(ours).toEqual(new Uint8Array(theirs));
    });

    it('matches libsodium with key', () => {
      const ours = sodium.crypto_generichash(32, msg, key32);
      const theirs = libsodium.crypto_generichash(32, msg, key32);
      expect(ours).toEqual(new Uint8Array(theirs));
    });

    it('matches libsodium with different output length', () => {
      const ours = sodium.crypto_generichash(28, msg);
      const theirs = libsodium.crypto_generichash(28, msg);
      expect(ours).toEqual(new Uint8Array(theirs));
    });
  });

  // --- Scalar operations ---

  describe('crypto_core_ed25519_scalar_add', () => {
    it('matches libsodium', () => {
      const a = new Uint8Array(32).fill(0x11);
      const b = new Uint8Array(32).fill(0x22);
      const ours = sodium.crypto_core_ed25519_scalar_add(a, b);
      const theirs = libsodium.crypto_core_ed25519_scalar_add(a, b);
      expect(ours).toEqual(new Uint8Array(theirs));
    });

    it('matches libsodium with overflow past L', () => {
      const big = new Uint8Array(32).fill(0xff);
      const ours = sodium.crypto_core_ed25519_scalar_add(big, big);
      const theirs = libsodium.crypto_core_ed25519_scalar_add(big, big);
      expect(ours).toEqual(new Uint8Array(theirs));
    });
  });

  describe('crypto_core_ed25519_scalar_mul', () => {
    it('matches libsodium', () => {
      const a = new Uint8Array(32).fill(0x03);
      const b = new Uint8Array(32).fill(0x07);
      const ours = sodium.crypto_core_ed25519_scalar_mul(a, b);
      const theirs = libsodium.crypto_core_ed25519_scalar_mul(a, b);
      expect(ours).toEqual(new Uint8Array(theirs));
    });
  });

  describe('crypto_core_ed25519_scalar_reduce', () => {
    it('matches libsodium with 64-byte input', () => {
      const ours = sodium.crypto_core_ed25519_scalar_reduce(key64);
      const theirs = libsodium.crypto_core_ed25519_scalar_reduce(key64);
      expect(ours).toEqual(new Uint8Array(theirs));
    });
  });

  // --- Point operations ---

  describe('crypto_scalarmult_ed25519_base_noclamp', () => {
    it('matches libsodium', () => {
      const scalar = new Uint8Array(32);
      scalar[0] = 7;
      const ours = sodium.crypto_scalarmult_ed25519_base_noclamp(scalar);
      const theirs = libsodium.crypto_scalarmult_ed25519_base_noclamp(scalar);
      expect(ours).toEqual(new Uint8Array(theirs));
    });

    it('matches libsodium with large scalar', () => {
      const scalar = new Uint8Array(32).fill(0xab);
      const ours = sodium.crypto_scalarmult_ed25519_base_noclamp(scalar);
      const theirs = libsodium.crypto_scalarmult_ed25519_base_noclamp(scalar);
      expect(ours).toEqual(new Uint8Array(theirs));
    });
  });

  describe('crypto_core_ed25519_add', () => {
    it('matches libsodium', () => {
      // Generate two valid points by multiplying base by different scalars
      const s1 = new Uint8Array(32);
      s1[0] = 3;
      const s2 = new Uint8Array(32);
      s2[0] = 5;
      const p1 = libsodium.crypto_scalarmult_ed25519_base_noclamp(s1);
      const p2 = libsodium.crypto_scalarmult_ed25519_base_noclamp(s2);

      const ours = sodium.crypto_core_ed25519_add(
        new Uint8Array(p1),
        new Uint8Array(p2),
      );
      const theirs = libsodium.crypto_core_ed25519_add(p1, p2);
      expect(ours).toEqual(new Uint8Array(theirs));
    });
  });

  // --- Signing ---

  describe('crypto_sign_seed_keypair', () => {
    it('matches libsodium', () => {
      const seed = new Uint8Array(32).fill(0x42);
      const ours = sodium.crypto_sign_seed_keypair(seed);
      const theirs = libsodium.crypto_sign_seed_keypair(seed);
      expect(ours.publicKey).toEqual(new Uint8Array(theirs.publicKey));
      expect(ours.privateKey).toEqual(new Uint8Array(theirs.privateKey));
    });
  });

  describe('crypto_sign_detached', () => {
    it('matches libsodium', () => {
      const seed = new Uint8Array(32).fill(0x42);
      const kp = libsodium.crypto_sign_seed_keypair(seed);
      const ours = sodium.crypto_sign_detached(msg, new Uint8Array(kp.privateKey));
      const theirs = libsodium.crypto_sign_detached(msg, kp.privateKey);
      expect(ours).toEqual(new Uint8Array(theirs));
    });
  });

  describe('crypto_sign_verify_detached', () => {
    it('verifies libsodium signature', () => {
      const seed = new Uint8Array(32).fill(0x42);
      const kp = libsodium.crypto_sign_seed_keypair(seed);
      const sig = libsodium.crypto_sign_detached(msg, kp.privateKey);
      expect(
        sodium.crypto_sign_verify_detached(
          new Uint8Array(sig),
          msg,
          new Uint8Array(kp.publicKey),
        ),
      ).toBe(true);
    });

    it('rejects invalid signature', () => {
      const seed = new Uint8Array(32).fill(0x42);
      const kp = libsodium.crypto_sign_seed_keypair(seed);
      const sig = new Uint8Array(64).fill(0);
      expect(
        sodium.crypto_sign_verify_detached(sig, msg, new Uint8Array(kp.publicKey)),
      ).toBe(false);
    });
  });

  // --- ready ---

  describe('ready', () => {
    it('resolves immediately', async () => {
      await expect(sodium.ready).resolves.toBeUndefined();
    });
  });
});
