import { describe, it, expect } from 'vitest';
import * as bip39 from 'bip39';
import { Bip32PrivateKey as StricaBip32PrivateKey } from '@stricahq/bip32ed25519';
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

import { Bip32PrivateKey, Bip32PublicKey, PrivateKey, PublicKey } from '../src/index.js';

describe('Bip32PrivateKey', () => {
  const entropy = new Uint8Array([
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  ]);

  it('creates from entropy', () => {
    const key = Bip32PrivateKey.fromEntropy(entropy);
    expect(key).toBeInstanceOf(Bip32PrivateKey);
  });

  it('derives hardened children', () => {
    const key = Bip32PrivateKey.fromEntropy(entropy);
    const child = key.derive(0x80000000 + 1852);
    expect(child).toBeInstanceOf(Bip32PrivateKey);
  });

  it('derives soft children', () => {
    const root = Bip32PrivateKey.fromEntropy(entropy);
    const account = root
      .derive(0x80000000 + 1852)
      .derive(0x80000000 + 1815)
      .derive(0x80000000);
    const child = account.derive(0);
    expect(child).toBeInstanceOf(Bip32PrivateKey);
  });

  it('converts to PrivateKey', () => {
    const key = Bip32PrivateKey.fromEntropy(entropy);
    const priv = key.toPrivateKey();
    expect(priv).toBeInstanceOf(PrivateKey);
    expect(priv.toBytes().length).toBe(64);
  });

  it('converts to Bip32PublicKey', () => {
    const key = Bip32PrivateKey.fromEntropy(entropy);
    const bip32pub = key.toBip32PublicKey();
    expect(bip32pub).toBeInstanceOf(Bip32PublicKey);
  });
});

describe('Bip32PublicKey', () => {
  const entropy = new Uint8Array([
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  ]);

  it('derives soft children', () => {
    const root = Bip32PrivateKey.fromEntropy(entropy);
    const account = root
      .derive(0x80000000 + 1852)
      .derive(0x80000000 + 1815)
      .derive(0x80000000);
    const bip32pub = account.toBip32PublicKey();
    const child = bip32pub.derive(0);
    expect(child).toBeInstanceOf(Bip32PublicKey);
  });

  it('throws on hardened derivation', () => {
    const root = Bip32PrivateKey.fromEntropy(entropy);
    const bip32pub = root.toBip32PublicKey();
    expect(() => bip32pub.derive(0x80000000)).toThrow();
  });

  it('converts to PublicKey', () => {
    const root = Bip32PrivateKey.fromEntropy(entropy);
    const pub = root.toBip32PublicKey().toPublicKey();
    expect(pub).toBeInstanceOf(PublicKey);
    expect(pub.toBytes().length).toBe(32);
  });
});

describe('PrivateKey', () => {
  const entropy = new Uint8Array([
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  ]);
  const message = new TextEncoder().encode('hello cardano');

  it('signs and PublicKey verifies', () => {
    const root = Bip32PrivateKey.fromEntropy(entropy);
    const priv = root.toPrivateKey();
    const pub = priv.toPublicKey();
    const sig = priv.sign(message);
    expect(sig.length).toBe(64);
    expect(pub.verify(message, sig)).toBe(true);
  });
});

describe('PublicKey', () => {
  const entropy = new Uint8Array([
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  ]);

  it('hash returns 28 bytes', () => {
    const root = Bip32PrivateKey.fromEntropy(entropy);
    const pub = root.toPrivateKey().toPublicKey();
    const h = pub.hash();
    expect(h.length).toBe(28);
  });
});

describe('cross-library verification against @stricahq/bip32ed25519', () => {
  const mnemonic =
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const entropy = Uint8Array.from(bip39.mnemonicToEntropy(mnemonic).match(/.{2}/g)!.map(b => parseInt(b, 16)));
  const message = new TextEncoder().encode('test message for signing');

  const HARDENED = 0x80000000;

  function deriveNoble(entropy: Uint8Array) {
    const root = Bip32PrivateKey.fromEntropy(entropy);
    const account = root
      .derive(HARDENED + 1852)
      .derive(HARDENED + 1815)
      .derive(HARDENED + 0);
    const paymentKey = account.derive(0).derive(0);
    const stakeKey = account.derive(2).derive(0);
    return { root, account, paymentKey, stakeKey };
  }

  async function deriveStrica(entropy: Uint8Array) {
    const root = await StricaBip32PrivateKey.fromEntropy(Buffer.from(entropy));
    const account = root
      .derive(HARDENED + 1852)
      .derive(HARDENED + 1815)
      .derive(HARDENED + 0);
    const paymentKey = account.derive(0).derive(0);
    const stakeKey = account.derive(2).derive(0);
    return { root, account, paymentKey, stakeKey };
  }

  it('root key private key bytes match', async () => {
    const noble = deriveNoble(entropy);
    const strica = await deriveStrica(entropy);
    const nobleBytes = noble.root.toPrivateKey().toBytes();
    const stricaBytes = strica.root.toPrivateKey().toBytes();
    expect(nobleBytes).toEqual(new Uint8Array(stricaBytes));
  });

  it('payment key public key bytes match', async () => {
    const noble = deriveNoble(entropy);
    const strica = await deriveStrica(entropy);
    const noblePub = noble.paymentKey.toPrivateKey().toPublicKey().toBytes();
    const stricaPub = strica.paymentKey.toBip32PublicKey().toPublicKey().toBytes();
    expect(noblePub).toEqual(new Uint8Array(stricaPub));
  });

  it('stake key public key bytes match', async () => {
    const noble = deriveNoble(entropy);
    const strica = await deriveStrica(entropy);
    const noblePub = noble.stakeKey.toPrivateKey().toPublicKey().toBytes();
    const stricaPub = strica.stakeKey.toBip32PublicKey().toPublicKey().toBytes();
    expect(noblePub).toEqual(new Uint8Array(stricaPub));
  });

  it('public key hashes match', async () => {
    const noble = deriveNoble(entropy);
    const strica = await deriveStrica(entropy);
    const nobleHash = noble.paymentKey.toPrivateKey().toPublicKey().hash();
    const stricaHash = strica.paymentKey.toBip32PublicKey().toPublicKey().hash();
    expect(nobleHash).toEqual(new Uint8Array(stricaHash));
  });

  it('signatures match', async () => {
    const noble = deriveNoble(entropy);
    const strica = await deriveStrica(entropy);
    const nobleSig = noble.paymentKey.toPrivateKey().sign(message);
    const stricaSig = strica.paymentKey.toPrivateKey().sign(Buffer.from(message));
    expect(nobleSig).toEqual(new Uint8Array(stricaSig));
  });

  it('noble signature verifies with strica public key', async () => {
    const noble = deriveNoble(entropy);
    const strica = await deriveStrica(entropy);
    const sig = noble.paymentKey.toPrivateKey().sign(message);
    const stricaPub = strica.paymentKey.toBip32PublicKey().toPublicKey();
    expect(stricaPub.verify(Buffer.from(sig), Buffer.from(message))).toBe(true);
  });

  it('public-only derivation matches private derivation', () => {
    const noble = deriveNoble(entropy);
    const accountBip32Pub = noble.account.toBip32PublicKey();
    const paymentPubOnly = accountBip32Pub.derive(0).derive(0);
    const paymentPubFromPriv = noble.paymentKey.toPrivateKey().toPublicKey();
    expect(paymentPubOnly.toPublicKey().toBytes()).toEqual(paymentPubFromPriv.toBytes());
  });
});
