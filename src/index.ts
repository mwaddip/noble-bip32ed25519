import {
  rootKeyFromEntropy,
  publicKeyFromPrivate,
  deriveChildHardened,
  deriveChildSoft,
  deriveChildSoftPublic,
  sign as cryptoSign,
  verify as cryptoVerify,
  hashPublicKey,
  type BIP32Key,
} from './crypto.js';

const HARDENED_THRESHOLD = 0x80000000;

export class Bip32PrivateKey {
  readonly #key: BIP32Key;

  private constructor(key: BIP32Key) {
    this.#key = key;
  }

  static fromEntropy(entropy: Uint8Array): Bip32PrivateKey {
    return new Bip32PrivateKey(rootKeyFromEntropy(entropy));
  }

  derive(index: number): Bip32PrivateKey {
    const child =
      index >= HARDENED_THRESHOLD
        ? deriveChildHardened(this.#key, index)
        : deriveChildSoft(this.#key, index);
    return new Bip32PrivateKey(child);
  }

  toPrivateKey(): PrivateKey {
    return new PrivateKey(this.#key.kL, this.#key.kR);
  }

  toBip32PublicKey(): Bip32PublicKey {
    const pubKey = publicKeyFromPrivate(this.#key.kL);
    return new Bip32PublicKey(pubKey, this.#key.chainCode);
  }
}

export class Bip32PublicKey {
  readonly #pubKey: Uint8Array;
  readonly #chainCode: Uint8Array;

  /** @internal */
  constructor(pubKey: Uint8Array, chainCode: Uint8Array) {
    this.#pubKey = pubKey;
    this.#chainCode = chainCode;
  }

  derive(index: number): Bip32PublicKey {
    if (index >= HARDENED_THRESHOLD) {
      throw new Error('Cannot derive hardened child from public key');
    }
    const { pubKey, chainCode } = deriveChildSoftPublic(
      this.#pubKey,
      this.#chainCode,
      index
    );
    return new Bip32PublicKey(pubKey, chainCode);
  }

  toPublicKey(): PublicKey {
    return new PublicKey(this.#pubKey);
  }
}

export class PrivateKey {
  readonly #kL: Uint8Array;
  readonly #kR: Uint8Array;

  /** @internal */
  constructor(kL: Uint8Array, kR: Uint8Array) {
    this.#kL = kL;
    this.#kR = kR;
  }

  toPublicKey(): PublicKey {
    return new PublicKey(publicKeyFromPrivate(this.#kL));
  }

  sign(message: Uint8Array): Uint8Array {
    return cryptoSign(this.#kL, this.#kR, message);
  }

  toBytes(): Uint8Array {
    const bytes = new Uint8Array(64);
    bytes.set(this.#kL, 0);
    bytes.set(this.#kR, 32);
    return bytes;
  }
}

export class PublicKey {
  readonly #pubKey: Uint8Array;

  /** @internal */
  constructor(pubKey: Uint8Array) {
    this.#pubKey = pubKey;
  }

  verify(message: Uint8Array, signature: Uint8Array): boolean {
    return cryptoVerify(this.#pubKey, message, signature);
  }

  toBytes(): Uint8Array {
    return Uint8Array.from(this.#pubKey);
  }

  hash(): Uint8Array {
    return hashPublicKey(this.#pubKey);
  }
}
