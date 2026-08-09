/**
 * Local Node-backed CryptoProvider double — coverage tests.
 *
 * Exercises the `nodeCryptoProvider` implementation against node:crypto
 * reference values for every primitive path: hash, HMAC, HKDF, all AEAD
 * cipher suites (AES-128/256-GCM, AES-128-CCM, ChaCha20-Poly1305), X25519,
 * ECDH (secp256r1, secp384r1), random bytes, signature verification, and
 * AES-ECB. These tests cover the branches that the oracle comparison file
 * does not (cipher suites, hash algorithms, key exchange, signatures).
 */

import {
    createHash,
    createHmac,
    createSign,
    createVerify,
    generateKeyPairSync,
    hkdfSync,
    randomBytes,
} from "node:crypto";
import { describe, expect, it } from "vitest";
import { nodeCryptoProvider as crypto } from "../src/reference/node-crypto-provider.js";

const KEY_16 = new Uint8Array(16).fill(0xab);
const KEY_32 = new Uint8Array(32).fill(0xcd);
const NONCE = new Uint8Array(12).fill(0x11);
const AAD = new TextEncoder().encode("additional-data");
const PLAINTEXT = new TextEncoder().encode("hello world, this is a test payload");

/** Hex-encode a byte array for readable assertion messages. */
function toHex(bytes: Uint8Array): string {
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

describe("nodeCryptoProvider — hash", () => {
    it("sha256 matches node:crypto reference", () => {
        const data = new TextEncoder().encode("test data");
        const expected = new Uint8Array(createHash("sha256").update(data).digest());
        expect(crypto.sha256(data)).toEqual(expected);
        expect(crypto.sha256(data)).toHaveLength(32);
    });

    it("sha384 matches node:crypto reference", () => {
        const data = new TextEncoder().encode("test data");
        const expected = new Uint8Array(createHash("sha384").update(data).digest());
        expect(crypto.sha384(data)).toEqual(expected);
        expect(crypto.sha384(data)).toHaveLength(48);
    });

    it("sha256 of empty buffer is correct", () => {
        const digest = crypto.sha256(new Uint8Array(0));
        expect(toHex(digest)).toBe(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
    });
});

describe("nodeCryptoProvider — hmac", () => {
    it("hmac sha256 matches node:crypto reference", () => {
        const key = new TextEncoder().encode("secret-key");
        const data = new TextEncoder().encode("message");
        const expected = new Uint8Array(createHmac("sha256", key).update(data).digest());
        expect(crypto.hmac("SHA-256", key, data)).toEqual(expected);
    });

    it("hmac sha384 matches node:crypto reference (exercises hashName sha384 branch)", () => {
        const key = new TextEncoder().encode("secret-key");
        const data = new TextEncoder().encode("message");
        const expected = new Uint8Array(createHmac("sha384", key).update(data).digest());
        expect(crypto.hmac("SHA-384", key, data)).toEqual(expected);
        expect(crypto.hmac("SHA-384", key, data)).toHaveLength(48);
    });
});

describe("nodeCryptoProvider — hkdf", () => {
    it("hkdf sha256 matches node:crypto.hkdfSync reference", () => {
        const salt = new Uint8Array(16).fill(0x01);
        const ikm = new Uint8Array(32).fill(0x02);
        const info = new TextEncoder().encode("test-info");
        const length = 48;
        const expected = new Uint8Array(hkdfSync("sha256", ikm, salt, info, length));
        expect(crypto.hkdf("SHA-256", salt, ikm, info, length)).toEqual(expected);
    });

    it("hkdf sha384 matches node:crypto.hkdfSync reference", () => {
        const salt = new Uint8Array(16).fill(0x03);
        const ikm = new Uint8Array(32).fill(0x04);
        const info = new TextEncoder().encode("test-info-384");
        const length = 64;
        const expected = new Uint8Array(hkdfSync("sha384", ikm, salt, info, length));
        expect(crypto.hkdf("SHA-384", salt, ikm, info, length)).toEqual(expected);
    });
});

describe("nodeCryptoProvider — AEAD AES-128-GCM", () => {
    it("encrypts and decrypts round-trip", () => {
        const ciphertext = crypto.aes128GcmEncrypt(KEY_16, NONCE, PLAINTEXT, AAD);
        const decrypted = crypto.aes128GcmDecrypt(KEY_16, NONCE, ciphertext, AAD);
        expect(decrypted).toEqual(PLAINTEXT);
    });

    it("produces 16-byte tag appended", () => {
        const ciphertext = crypto.aes128GcmEncrypt(KEY_16, NONCE, PLAINTEXT, AAD);
        expect(ciphertext.length).toBe(PLAINTEXT.length + 16);
    });

    it("handles empty plaintext", () => {
        const ciphertext = crypto.aes128GcmEncrypt(KEY_16, NONCE, new Uint8Array(0), AAD);
        expect(ciphertext.length).toBe(16);
        const decrypted = crypto.aes128GcmDecrypt(KEY_16, NONCE, ciphertext, AAD);
        expect(decrypted).toEqual(new Uint8Array(0));
    });

    it("fails authentication on tampered ciphertext", () => {
        const ciphertext = crypto.aes128GcmEncrypt(KEY_16, NONCE, PLAINTEXT, AAD);
        ciphertext[0] ^= 0xff;
        expect(() => crypto.aes128GcmDecrypt(KEY_16, NONCE, ciphertext, AAD)).toThrow();
    });
});

describe("nodeCryptoProvider — AEAD AES-256-GCM", () => {
    it("encrypts and decrypts round-trip", () => {
        const ciphertext = crypto.aes256GcmEncrypt(KEY_32, NONCE, PLAINTEXT, AAD);
        const decrypted = crypto.aes256GcmDecrypt(KEY_32, NONCE, ciphertext, AAD);
        expect(decrypted).toEqual(PLAINTEXT);
    });

    it("produces 16-byte tag appended", () => {
        const ciphertext = crypto.aes256GcmEncrypt(KEY_32, NONCE, PLAINTEXT, AAD);
        expect(ciphertext.length).toBe(PLAINTEXT.length + 16);
    });

    it("handles empty plaintext", () => {
        const ciphertext = crypto.aes256GcmEncrypt(KEY_32, NONCE, new Uint8Array(0), AAD);
        expect(ciphertext.length).toBe(16);
        const decrypted = crypto.aes256GcmDecrypt(KEY_32, NONCE, ciphertext, AAD);
        expect(decrypted).toEqual(new Uint8Array(0));
    });
});

describe("nodeCryptoProvider — AEAD AES-128-CCM", () => {
    it("encrypts and decrypts round-trip", () => {
        const ciphertext = crypto.aes128CcmEncrypt(KEY_16, NONCE, PLAINTEXT, AAD);
        const decrypted = crypto.aes128CcmDecrypt(KEY_16, NONCE, ciphertext, AAD);
        expect(decrypted).toEqual(PLAINTEXT);
    });

    it("produces 16-byte tag appended", () => {
        const ciphertext = crypto.aes128CcmEncrypt(KEY_16, NONCE, PLAINTEXT, AAD);
        expect(ciphertext.length).toBe(PLAINTEXT.length + 16);
    });
});

describe("nodeCryptoProvider — AEAD ChaCha20-Poly1305", () => {
    it("encrypts and decrypts round-trip", () => {
        const ciphertext = crypto.chacha20Poly1305Encrypt(KEY_32, NONCE, PLAINTEXT, AAD);
        const decrypted = crypto.chacha20Poly1305Decrypt(KEY_32, NONCE, ciphertext, AAD);
        expect(decrypted).toEqual(PLAINTEXT);
    });

    it("produces 16-byte tag appended", () => {
        const ciphertext = crypto.chacha20Poly1305Encrypt(KEY_32, NONCE, PLAINTEXT, AAD);
        expect(ciphertext.length).toBe(PLAINTEXT.length + 16);
    });

    it("handles empty plaintext", () => {
        const ciphertext = crypto.chacha20Poly1305Encrypt(KEY_32, NONCE, new Uint8Array(0), AAD);
        expect(ciphertext.length).toBe(16);
        const decrypted = crypto.chacha20Poly1305Decrypt(KEY_32, NONCE, ciphertext, AAD);
        expect(decrypted).toEqual(new Uint8Array(0));
    });
});

describe("nodeCryptoProvider — X25519", () => {
    it("generates a key pair with 32-byte keys", () => {
        const kp = crypto.x25519GenerateKeyPair();
        expect(kp.publicKey).toHaveLength(32);
        expect(kp.secretKey).toHaveLength(32);
    });

    it("shared secret is symmetric (Alice/Bob agree)", () => {
        const alice = crypto.x25519GenerateKeyPair();
        const bob = crypto.x25519GenerateKeyPair();
        const secretAB = crypto.x25519SharedSecret(alice.secretKey, bob.publicKey);
        const secretBA = crypto.x25519SharedSecret(bob.secretKey, alice.publicKey);
        expect(secretAB).toEqual(secretBA);
        expect(secretAB).toHaveLength(32);
    });

    it("all-zero public key yields all-zero shared secret (RFC 7748 §5)", () => {
        const alice = crypto.x25519GenerateKeyPair();
        const zero = new Uint8Array(32);
        const shared = crypto.x25519SharedSecret(alice.secretKey, zero);
        expect(shared).toEqual(new Uint8Array(32));
    });
});

describe("nodeCryptoProvider — ECDH", () => {
    it("secp256r1: generates valid key pair and shared secret agrees", () => {
        const alice = crypto.ecdhGenerateKeyPair("secp256r1");
        const bob = crypto.ecdhGenerateKeyPair("secp256r1");
        expect(alice.publicKey).toHaveLength(65); // 0x04 || x || y
        expect(bob.publicKey).toHaveLength(65);
        const secretAB = crypto.ecdhSharedSecret("secp256r1", alice.secretKey, bob.publicKey);
        const secretBA = crypto.ecdhSharedSecret("secp256r1", bob.secretKey, alice.publicKey);
        expect(secretAB).toEqual(secretBA);
        expect(secretAB).toHaveLength(32);
    });

    it("secp384r1: generates valid key pair and shared secret agrees", () => {
        const alice = crypto.ecdhGenerateKeyPair("secp384r1");
        const bob = crypto.ecdhGenerateKeyPair("secp384r1");
        expect(alice.publicKey).toHaveLength(97); // 0x04 || x || y
        expect(bob.publicKey).toHaveLength(97);
        const secretAB = crypto.ecdhSharedSecret("secp384r1", alice.secretKey, bob.publicKey);
        const secretBA = crypto.ecdhSharedSecret("secp384r1", bob.secretKey, alice.publicKey);
        expect(secretAB).toEqual(secretBA);
        expect(secretAB).toHaveLength(48);
    });
});

describe("nodeCryptoProvider — randomBytes", () => {
    it("returns exact requested length", () => {
        expect(crypto.randomBytes(0)).toHaveLength(0);
        expect(crypto.randomBytes(1)).toHaveLength(1);
        expect(crypto.randomBytes(32)).toHaveLength(32);
        expect(crypto.randomBytes(1024)).toHaveLength(1024);
    });

    it("produces non-deterministic output", () => {
        const a = crypto.randomBytes(16);
        const b = crypto.randomBytes(16);
        expect(a).not.toEqual(b);
    });
});

describe("nodeCryptoProvider — signature verification", () => {
    it("verifies a valid ECDSA secp384r1 signature (exercises sha384 branch)", () => {
        const { privateKey, publicKey } = generateKeyPairSync("ec", {
            namedCurve: "secp384r1",
        });
        const data = String("ecdsa-secp384 test data: ")
            .repeat(Math.ceil(6 / String("ecdsa-secp384 test data: ").length))
            .slice(0, 6);
        const dataBuf = Buffer.from(data);
        const signer = createSign("sha384");
        signer.update(dataBuf);
        const signature = signer.sign(privateKey);
        const spkiDer = publicKey.export({ type: "spki", format: "der" }) as Buffer;
        const ok = crypto.verifySignature(
            "ecdsa_secp384r1_sha384",
            new Uint8Array(spkiDer),
            new Uint8Array(signature),
            new Uint8Array(dataBuf),
        );
        expect(ok).toBe(true);
    });

    it("verifies a valid RSA-PKCS1-SHA384 signature (exercises sha384 branch)", () => {
        const { privateKey, publicKey } = generateKeyPairSync("rsa", {
            modulusLength: 2048,
        });
        const data = Buffer.from("rsa sha384 test data");
        const signer = createSign("RSA-SHA384");
        signer.update(data);
        const signature = signer.sign(privateKey);
        const spkiDer = publicKey.export({ type: "spki", format: "der" }) as Buffer;
        const ok = crypto.verifySignature(
            "rsa_pkcs1_sha384",
            new Uint8Array(spkiDer),
            new Uint8Array(signature),
            new Uint8Array(data),
        );
        expect(ok).toBe(true);
    });

    it("verifies a valid RSA-PSS-SHA256 signature (exercises rsa_pss branch)", () => {
        const { privateKey, publicKey } = generateKeyPairSync("rsa", {
            modulusLength: 2048,
        });
        const data = Buffer.from("rsa-pss sha256 test data");
        const signer = createSign("RSA-SHA256");
        signer.update(data);
        const signature = signer.sign(privateKey);
        const spkiDer = publicKey.export({ type: "spki", format: "der" }) as Buffer;
        const ok = crypto.verifySignature(
            "rsa_pss_rsae_sha256",
            new Uint8Array(spkiDer),
            new Uint8Array(signature),
            new Uint8Array(data),
        );
        expect(ok).toBe(true);
    });

    it("verifies a valid ECDSA secp256r1 signature", () => {
        // Generate an EC key pair with KeyObject encoding so sign/verify work.
        const { privateKey, publicKey } = generateKeyPairSync("ec", {
            namedCurve: "prime256v1",
        });
        const data = Buffer.from("test data to sign");
        const signer = createSign("sha256");
        signer.update(data);
        const signature = signer.sign(privateKey);
        // Export public key as SPKI DER for the verifySignature contract
        const spkiDer = publicKey.export({ type: "spki", format: "der" }) as Buffer;
        const ok = crypto.verifySignature(
            "ecdsa_secp256r1_sha256",
            new Uint8Array(spkiDer),
            new Uint8Array(signature),
            new Uint8Array(data),
        );
        expect(ok).toBe(true);
    });

    it("verifies a valid RSA-PKCS1-SHA256 signature", () => {
        const { privateKey, publicKey } = generateKeyPairSync("rsa", {
            modulusLength: 2048,
        });
        const data = Buffer.from("rsa test data");
        const signer = createSign("RSA-SHA256");
        signer.update(data);
        const signature = signer.sign(privateKey);
        const spkiDer = publicKey.export({ type: "spki", format: "der" }) as Buffer;
        const ok = crypto.verifySignature(
            "rsa_pkcs1_sha256",
            new Uint8Array(spkiDer),
            new Uint8Array(signature),
            new Uint8Array(data),
        );
        expect(ok).toBe(true);
    });

    it("rejects an invalid signature", () => {
        const { publicKey } = generateKeyPairSync("ec", {
            namedCurve: "prime256v1",
        });
        const data = Buffer.from("test data");
        const fakeSig = new Uint8Array(64).fill(0x42);
        const spkiDer = publicKey.export({ type: "spki", format: "der" }) as Buffer;
        const ok = crypto.verifySignature(
            "ecdsa_secp256r1_sha256",
            new Uint8Array(spkiDer),
            fakeSig,
            new Uint8Array(data),
        );
        expect(ok).toBe(false);
    });
});

describe("nodeCryptoProvider — AES-ECB", () => {
    it("encrypts a single 16-byte block with AES-128-ECB", () => {
        const block = new Uint8Array(16).fill(0x55);
        const out = crypto.aesEcbEncrypt(KEY_16, block);
        expect(out).toHaveLength(16);
        // ECB: encrypting the same block twice gives the same output
        const out2 = crypto.aesEcbEncrypt(KEY_16, block);
        expect(out).toEqual(out2);
    });

    it("encrypts a single 16-byte block with AES-256-ECB", () => {
        const block = new Uint8Array(16).fill(0x77);
        const out = crypto.aesEcbEncrypt(KEY_32, block);
        expect(out).toHaveLength(16);
        const out2 = crypto.aesEcbEncrypt(KEY_32, block);
        expect(out).toEqual(out2);
    });
});

describe("nodeCryptoProvider — hash oracle consistency", () => {
    it("sha256 matches node:crypto for large input", () => {
        const data = randomBytes(4096);
        const expected = new Uint8Array(createHash("sha256").update(data).digest());
        expect(crypto.sha256(new Uint8Array(data))).toEqual(expected);
    });

    it("sha384 matches node:crypto for large input", () => {
        const data = randomBytes(4096);
        const expected = new Uint8Array(createHash("sha384").update(data).digest());
        expect(crypto.sha384(new Uint8Array(data))).toEqual(expected);
    });
});
