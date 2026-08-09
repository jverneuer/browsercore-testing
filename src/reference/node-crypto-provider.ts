/**
 * Local Node-backed CryptoProvider double.
 *
 * @browsercore/crypto 0.2.2 exports only types, errors, and utilities — the
 * runtime NodeCryptoProvider implementation lives in
 * `browsersmith/src/platform/crypto/node/`. This repo (Layer 4) cannot depend
 * on browsersmith (Layer 5), so we provide a local Node-backed implementation
 * of the `CryptoProvider` contract for tests and e2e harnesses.
 *
 * This double mirrors the production NodeCryptoProvider behavior:
 * - Hashing via node:crypto (sha256, sha384)
 * - HKDF via node:crypto.hkdfSync
 * - HMAC via node:crypto.createHmac
 * - AEAD via node:crypto.createCipheriv/createDecipheriv (GCM, CCM, ChaCha20)
 * - X25519 via NobleX25519Backend (pure JS, no native binding)
 * - ECDH via node:crypto.ECDH
 * - Signatures via node:crypto.createVerify
 * - Random bytes via node:crypto.randomBytes
 *
 * The production provider uses the same primitives — this double exists only
 * because the package boundary moved the implementation to a higher layer.
 */

import {
    createCipheriv,
    createDecipheriv,
    createECDH,
    createHash,
    createHmac,
    createVerify,
    hkdfSync,
    randomBytes,
} from "node:crypto";
import type {
    CryptoProvider,
    EcdhCurve,
    EcdhKeyPair,
    HashId,
    X25519KeyPair,
} from "@browsercore/crypto";
import { NobleX25519Backend } from "@browsercore/crypto";

const noble = new NobleX25519Backend();

/** Curve → node:crypto named curve + expected coordinate length. */
const ECDH_CURVE_PARAMS: Record<EcdhCurve, { readonly nodeCurve: string; readonly coordLen: number }> = {
    secp256r1: { nodeCurve: "prime256v1", coordLen: 32 },
    secp384r1: { nodeCurve: "secp384r1", coordLen: 48 },
};

/** Map our HashId branded union to node:crypto's hash algorithm name. */
function hashName(hash: HashId): string {
    return hash === "SHA-256" ? "sha256" : "sha384";
}

/**
 * Convert a Uint8Array to a node Buffer for cipher APIs.
 * Newer @types/node BinaryLike excludes bare ArrayBuffer — Buffer is always safe.
 */
function toBuf(data: Uint8Array): Buffer {
    return Buffer.from(data);
}

/**
 * Map a 12-byte AEAD nonce to a node:crypto IV (Buffer).
 * Used uniformly by every AEAD path so the conversion happens in one place.
 */
function toIv(nonce: Uint8Array): Buffer {
    return Buffer.from(nonce);
}

/**
 * Node-backed CryptoProvider implementation.
 *
 * Satisfies the full `CryptoProvider` contract using node:crypto + noble-curves.
 * Safe for tests and e2e harnesses — never imported by production protocol code.
 */
export const nodeCryptoProvider: CryptoProvider = {
    randomBytes(length: number): Uint8Array {
        return new Uint8Array(randomBytes(length));
    },

    sha256(data: Uint8Array): Uint8Array {
        return new Uint8Array(createHash("sha256").update(toBuf(data)).digest());
    },

    sha384(data: Uint8Array): Uint8Array {
        return new Uint8Array(createHash("sha384").update(toBuf(data)).digest());
    },

    hkdf(hash: HashId, salt: Uint8Array, ikm: Uint8Array, info: Uint8Array, length: number): Uint8Array {
        return new Uint8Array(hkdfSync(hashName(hash), toBuf(ikm), toBuf(salt), toBuf(info), length));
    },

    hmac(hash: HashId, key: Uint8Array, data: Uint8Array): Uint8Array {
        return new Uint8Array(createHmac(hashName(hash), toBuf(key)).update(toBuf(data)).digest());
    },

    aes128GcmEncrypt(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Uint8Array {
        const cipher = createCipheriv("aes-128-gcm", toBuf(key), toIv(nonce));
        cipher.setAAD(toBuf(aad));
        const ciphertext = Buffer.concat([cipher.update(toBuf(plaintext)), cipher.final()]);
        const tag = cipher.getAuthTag();
        return new Uint8Array(Buffer.concat([ciphertext, tag]));
    },

    aes128GcmDecrypt(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, aad: Uint8Array): Uint8Array {
        const tagLen = 16;
        const enc = ciphertext.subarray(0, ciphertext.length - tagLen);
        const tag = ciphertext.subarray(ciphertext.length - tagLen);
        const decipher = createDecipheriv("aes-128-gcm", toBuf(key), toIv(nonce));
        decipher.setAuthTag(toBuf(tag));
        decipher.setAAD(toBuf(aad));
        return new Uint8Array(Buffer.concat([decipher.update(toBuf(enc)), decipher.final()]));
    },

    aes256GcmEncrypt(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Uint8Array {
        const cipher = createCipheriv("aes-256-gcm", toBuf(key), toIv(nonce));
        cipher.setAAD(toBuf(aad));
        const ciphertext = Buffer.concat([cipher.update(toBuf(plaintext)), cipher.final()]);
        const tag = cipher.getAuthTag();
        return new Uint8Array(Buffer.concat([ciphertext, tag]));
    },

    aes256GcmDecrypt(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, aad: Uint8Array): Uint8Array {
        const tagLen = 16;
        const enc = ciphertext.subarray(0, ciphertext.length - tagLen);
        const tag = ciphertext.subarray(ciphertext.length - tagLen);
        const decipher = createDecipheriv("aes-256-gcm", toBuf(key), toIv(nonce));
        decipher.setAuthTag(toBuf(tag));
        decipher.setAAD(toBuf(aad));
        return new Uint8Array(Buffer.concat([decipher.update(toBuf(enc)), decipher.final()]));
    },

    aes128CcmEncrypt(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Uint8Array {
        const cipher = createCipheriv("aes-128-ccm", toBuf(key), toIv(nonce), {
            authTagLength: 16,
        });
        cipher.setAAD(toBuf(aad), { plaintextLength: plaintext.length });
        const ciphertext = Buffer.concat([cipher.update(toBuf(plaintext)), cipher.final()]);
        const tag = cipher.getAuthTag();
        return new Uint8Array(Buffer.concat([ciphertext, tag]));
    },

    aes128CcmDecrypt(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, aad: Uint8Array): Uint8Array {
        const tagLen = 16;
        const enc = ciphertext.subarray(0, ciphertext.length - tagLen);
        const tag = ciphertext.subarray(ciphertext.length - tagLen);
        const decipher = createDecipheriv("aes-128-ccm", toBuf(key), toIv(nonce), {
            authTagLength: 16,
        });
        decipher.setAuthTag(toBuf(tag));
        decipher.setAAD(toBuf(aad), { plaintextLength: enc.length });
        return new Uint8Array(Buffer.concat([decipher.update(toBuf(enc)), decipher.final()]));
    },

    chacha20Poly1305Encrypt(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Uint8Array {
        const cipher = createCipheriv("chacha20-poly1305", toBuf(key), toIv(nonce), {
            authTagLength: 16,
        });
        cipher.setAAD(toBuf(aad));
        const ciphertext = Buffer.concat([cipher.update(toBuf(plaintext)), cipher.final()]);
        const tag = cipher.getAuthTag();
        return new Uint8Array(Buffer.concat([ciphertext, tag]));
    },

    chacha20Poly1305Decrypt(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, aad: Uint8Array): Uint8Array {
        const tagLen = 16;
        const enc = ciphertext.subarray(0, ciphertext.length - tagLen);
        const tag = ciphertext.subarray(ciphertext.length - tagLen);
        const decipher = createDecipheriv("chacha20-poly1305", toBuf(key), toIv(nonce), {
            authTagLength: 16,
        });
        decipher.setAuthTag(toBuf(tag));
        decipher.setAAD(toBuf(aad));
        return new Uint8Array(Buffer.concat([decipher.update(toBuf(enc)), decipher.final()]));
    },

    x25519GenerateKeyPair(): X25519KeyPair {
        const secretKey = this.randomBytes(32);
        const publicKey = noble.publicKey(secretKey);
        return { publicKey, secretKey };
    },

    x25519SharedSecret(secretKey: Uint8Array, peerPublicKey: Uint8Array): Uint8Array {
        return noble.sharedSecret(secretKey, peerPublicKey);
    },

    ecdhGenerateKeyPair(curve: EcdhCurve): EcdhKeyPair {
        const params = ECDH_CURVE_PARAMS[curve];
        const ecdh = createECDH(params.nodeCurve);
        ecdh.generateKeys();
        const publicKey = ecdh.getPublicKey(null, "uncompressed");
        const secretKey = ecdh.getPrivateKey();
        return {
            curve,
            publicKey: new Uint8Array(publicKey),
            secretKey: new Uint8Array(secretKey),
        };
    },

    ecdhSharedSecret(curve: EcdhCurve, secretKey: Uint8Array, peerPublicKey: Uint8Array): Uint8Array {
        const params = ECDH_CURVE_PARAMS[curve];
        const ecdh = createECDH(params.nodeCurve);
        ecdh.setPrivateKey(toBuf(secretKey));
        const shared = ecdh.computeSecret(toBuf(peerPublicKey));
        return new Uint8Array(shared.subarray(shared.length - params.coordLen));
    },

    verifySignature(scheme: string, publicKey: Uint8Array, signature: Uint8Array, data: Uint8Array): boolean {
        const verifier = createVerify(verificationHash(scheme));
        verifier.update(toBuf(data));
        return verifier.verify(
            { key: toBuf(publicKey), format: "der", type: "spki" },
            toBuf(signature),
        );
    },

    aesEcbEncrypt(key: Uint8Array, block: Uint8Array): Uint8Array {
        const cipher = createCipheriv(
            key.length === 16 ? "aes-128-ecb" : "aes-256-ecb",
            toBuf(key),
            null,
        );
        cipher.setAutoPadding(false);
        return new Uint8Array(cipher.update(toBuf(block)));
    },
};

/**
 * Map a TLS signature-scheme name to a node:crypto verification hash.
 * Only the schemes the test suite exercises are covered.
 */
function verificationHash(scheme: string): string {
    switch (scheme) {
        case "ecdsa_secp256r1_sha256":
        case "rsa_pss_rsae_sha256":
        case "rsa_pkcs1_sha256":
            return "sha256";
        case "ecdsa_secp384r1_sha384":
        case "rsa_pss_rsae_sha384":
        case "rsa_pkcs1_sha384":
            return "sha384";
        default:
            return "sha256";
    }
}
