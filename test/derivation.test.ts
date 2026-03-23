import { describe, it, expect } from 'vitest';
import {
  rootKeyFromEntropy,
  publicKeyFromPrivate,
  deriveChildHardened,
  deriveChildSoft,
  deriveChildSoftPublic,
  sign,
  verify,
  hashPublicKey,
} from '../src/crypto.js';

const entropy = new Uint8Array([
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
]);

describe('rootKeyFromEntropy', () => {
  it('returns 32-byte kL, 32-byte kR, 32-byte chainCode', () => {
    const { kL, kR, chainCode } = rootKeyFromEntropy(entropy);
    expect(kL).toBeInstanceOf(Uint8Array);
    expect(kL.length).toBe(32);
    expect(kR).toBeInstanceOf(Uint8Array);
    expect(kR.length).toBe(32);
    expect(chainCode).toBeInstanceOf(Uint8Array);
    expect(chainCode.length).toBe(32);
  });

  it('clamps kL correctly', () => {
    const { kL } = rootKeyFromEntropy(entropy);
    expect(kL[0] & 0x07).toBe(0);
    expect(kL[31] & 0xE0).toBe(0x40);
  });

  it('rejects invalid entropy length', () => {
    expect(() => rootKeyFromEntropy(new Uint8Array(15))).toThrow();
    expect(() => rootKeyFromEntropy(new Uint8Array(33))).toThrow();
  });

  it('is deterministic', () => {
    const a = rootKeyFromEntropy(entropy);
    const b = rootKeyFromEntropy(entropy);
    expect(a.kL).toEqual(b.kL);
    expect(a.kR).toEqual(b.kR);
    expect(a.chainCode).toEqual(b.chainCode);
  });
});

describe('publicKeyFromPrivate', () => {
  it('returns a 32-byte public key', () => {
    const { kL } = rootKeyFromEntropy(entropy);
    const pub = publicKeyFromPrivate(kL);
    expect(pub).toBeInstanceOf(Uint8Array);
    expect(pub.length).toBe(32);
  });

  it('is deterministic', () => {
    const { kL } = rootKeyFromEntropy(entropy);
    const a = publicKeyFromPrivate(kL);
    const b = publicKeyFromPrivate(kL);
    expect(a).toEqual(b);
  });
});

describe('deriveChildHardened', () => {
  it('derives a valid child key', () => {
    const root = rootKeyFromEntropy(entropy);
    const child = deriveChildHardened(root, 0x80000000);
    expect(child.kL.length).toBe(32);
    expect(child.kR.length).toBe(32);
    expect(child.chainCode.length).toBe(32);
  });

  it('preserves clamping on child kL', () => {
    const root = rootKeyFromEntropy(entropy);
    const child = deriveChildHardened(root, 0x80000000);
    expect(child.kL[0] & 0x07).toBe(0);
  });

  it('different indices produce different keys', () => {
    const root = rootKeyFromEntropy(entropy);
    const child1 = deriveChildHardened(root, 0x80000000);
    const child2 = deriveChildHardened(root, 0x80000001);
    expect(child1.kL).not.toEqual(child2.kL);
  });

  it('is deterministic', () => {
    const root = rootKeyFromEntropy(entropy);
    const a = deriveChildHardened(root, 0x80000000);
    const b = deriveChildHardened(root, 0x80000000);
    expect(a.kL).toEqual(b.kL);
    expect(a.kR).toEqual(b.kR);
    expect(a.chainCode).toEqual(b.chainCode);
  });
});

describe('deriveChildSoft', () => {
  function getAccountKey() {
    const root = rootKeyFromEntropy(entropy);
    const purpose = deriveChildHardened(root, 0x80000000 + 1852);
    const coinType = deriveChildHardened(purpose, 0x80000000 + 1815);
    return deriveChildHardened(coinType, 0x80000000);
  }

  it('derives a valid child key with soft index', () => {
    const account = getAccountKey();
    const child = deriveChildSoft(account, 0);
    expect(child.kL.length).toBe(32);
    expect(child.kR.length).toBe(32);
    expect(child.chainCode.length).toBe(32);
  });

  it('child public key matches derivation from child private key', () => {
    const account = getAccountKey();
    const child = deriveChildSoft(account, 0);
    const pubFromPriv = publicKeyFromPrivate(child.kL);
    expect(pubFromPriv.length).toBe(32);
  });

  it('different indices produce different keys', () => {
    const account = getAccountKey();
    const child0 = deriveChildSoft(account, 0);
    const child1 = deriveChildSoft(account, 1);
    expect(child0.kL).not.toEqual(child1.kL);
  });

  it('is deterministic', () => {
    const account = getAccountKey();
    const a = deriveChildSoft(account, 0);
    const b = deriveChildSoft(account, 0);
    expect(a.kL).toEqual(b.kL);
  });
});

describe('deriveChildSoftPublic', () => {
  function getAccountKey() {
    const root = rootKeyFromEntropy(entropy);
    const purpose = deriveChildHardened(root, 0x80000000 + 1852);
    const coinType = deriveChildHardened(purpose, 0x80000000 + 1815);
    return deriveChildHardened(coinType, 0x80000000);
  }

  it('public-only derivation matches private derivation', () => {
    const account = getAccountKey();
    const accountPub = publicKeyFromPrivate(account.kL);

    const childPriv = deriveChildSoft(account, 0);
    const childPubFromPriv = publicKeyFromPrivate(childPriv.kL);

    const { pubKey: childPubFromPub } = deriveChildSoftPublic(
      accountPub,
      account.chainCode,
      0
    );

    expect(childPubFromPub).toEqual(childPubFromPriv);
  });

  it('chain codes match between private and public derivation', () => {
    const account = getAccountKey();
    const accountPub = publicKeyFromPrivate(account.kL);

    const childPriv = deriveChildSoft(account, 0);
    const { chainCode: pubChainCode } = deriveChildSoftPublic(
      accountPub,
      account.chainCode,
      0
    );

    expect(pubChainCode).toEqual(childPriv.chainCode);
  });
});

describe('sign and verify', () => {
  const message = new TextEncoder().encode('hello cardano');

  it('produces a 64-byte signature', () => {
    const { kL, kR } = rootKeyFromEntropy(entropy);
    const sig = sign(kL, kR, message);
    expect(sig).toBeInstanceOf(Uint8Array);
    expect(sig.length).toBe(64);
  });

  it('signature verifies with correct public key', () => {
    const { kL, kR } = rootKeyFromEntropy(entropy);
    const pubKey = publicKeyFromPrivate(kL);
    const sig = sign(kL, kR, message);
    expect(verify(pubKey, message, sig)).toBe(true);
  });

  it('verification fails with wrong message', () => {
    const { kL, kR } = rootKeyFromEntropy(entropy);
    const pubKey = publicKeyFromPrivate(kL);
    const sig = sign(kL, kR, message);
    const wrongMsg = new TextEncoder().encode('wrong message');
    expect(verify(pubKey, wrongMsg, sig)).toBe(false);
  });

  it('verification fails with wrong public key', () => {
    const { kL, kR } = rootKeyFromEntropy(entropy);
    const sig = sign(kL, kR, message);
    const other = rootKeyFromEntropy(new Uint8Array(16).fill(0xff));
    const wrongPub = publicKeyFromPrivate(other.kL);
    expect(verify(wrongPub, message, sig)).toBe(false);
  });

  it('is deterministic', () => {
    const { kL, kR } = rootKeyFromEntropy(entropy);
    const sig1 = sign(kL, kR, message);
    const sig2 = sign(kL, kR, message);
    expect(sig1).toEqual(sig2);
  });
});

describe('hashPublicKey', () => {
  it('returns 28 bytes (blake2b-224)', () => {
    const { kL } = rootKeyFromEntropy(entropy);
    const pub = publicKeyFromPrivate(kL);
    const h = hashPublicKey(pub);
    expect(h).toBeInstanceOf(Uint8Array);
    expect(h.length).toBe(28);
  });

  it('is deterministic', () => {
    const { kL } = rootKeyFromEntropy(entropy);
    const pub = publicKeyFromPrivate(kL);
    expect(hashPublicKey(pub)).toEqual(hashPublicKey(pub));
  });
});
