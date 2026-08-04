/**
 * Self-signed ECDSA P-256 certificate generator for the E2E TLS sink server.
 *
 * Builds a minimal X.509v3 certificate DER at runtime via `node:crypto` — no
 * `openssl` binary, no external deps. Mirrors the DER-builder pattern from
 * `tls/tests/server-sim.ts` but adds a SubjectAlternativeName extension so
 * the cert is valid for both `127.0.0.1` (IP) and `localhost` (DNS), which is
 * what the sink's consumers need.
 *
 * The cert is leaf-only (no CA chain), self-signed, and uses the
 * `ecdsa-with-SHA256` signature algorithm over the P-256 curve — the same
 * combination real CAs issue for TLS 1.3 handshakes.
 */

import { createSign, generateKeyPairSync } from "node:crypto";

/** A self-signed leaf certificate + its private key, both in DER/PEM form. */
export interface SelfSignedCert {
    /** DER-encoded leaf certificate. */
    readonly certDer: Uint8Array;
    /** PEM-encoded PKCS#8 private key (for `tls.createSecureContext`). */
    readonly keyPem: string;
}

// --- DER builders -------------------------------------------------------
// All builders return a DER-encoded TLV. Tag classes are universal unless noted.

function concatBytes(...chunks: readonly Uint8Array[]): Uint8Array {
    const total = chunks.reduce((s, c) => s + c.length, 0);
    const out = new Uint8Array(total);
    let o = 0;
    for (const c of chunks) {
        out.set(c, o);
        o += c.length;
    }
    return out;
}

/** Encode a DER length (definite short/long form up to 65535). */
function derLength(length: number): Uint8Array {
    if (length < 0x80) return new Uint8Array([length]);
    if (length < 0x100) return new Uint8Array([0x81, length]);
    return new Uint8Array([0x82, (length >> 8) & 0xff, length & 0xff]);
}

/** Wrap content in a DER TLV with the given tag. */
function derTagged(tag: number, content: Uint8Array): Uint8Array {
    return concatBytes(new Uint8Array([tag]), derLength(content.length), content);
}

function derSequence(...parts: readonly Uint8Array[]): Uint8Array {
    return derTagged(0x30, concatBytes(...parts));
}
function derSet(...parts: readonly Uint8Array[]): Uint8Array {
    return derTagged(0x31, concatBytes(...parts));
}
function derNull(): Uint8Array {
    return new Uint8Array([0x05, 0x00]);
}
function derBooleanTrue(): Uint8Array {
    return new Uint8Array([0x01, 0x01, 0xff]);
}
function derInteger(value: Uint8Array): Uint8Array {
    const needsPad = value.length > 0 && (value[0]! & 0x80) !== 0;
    return derTagged(0x02, needsPad ? concatBytes(new Uint8Array([0x00]), value) : value);
}
function derBitString(content: Uint8Array): Uint8Array {
    return derTagged(0x03, concatBytes(new Uint8Array([0x00]), content));
}
function derOctetString(content: Uint8Array): Uint8Array {
    return derTagged(0x04, content);
}
function derUtf8String(bytes: Uint8Array): Uint8Array {
    return derTagged(0x0c, bytes);
}
function derGeneralizedTime(text: string): Uint8Array {
    return derTagged(0x18, new TextEncoder().encode(text));
}
function derOid(oid: string): Uint8Array {
    const parts = oid.split(".").map((p) => Number.parseInt(p, 10));
    const first = parts[0]! * 40 + parts[1]!;
    const rest: number[] = [];
    for (const arc of parts.slice(2)) {
        if (arc === 0) {
            rest.push(0);
            continue;
        }
        const bytes: number[] = [];
        let value = arc;
        while (value > 0) {
            bytes.unshift((value & 0x7f) | (bytes.length === 0 ? 0 : 0x80));
            value >>= 7;
        }
        rest.push(...bytes);
    }
    return derTagged(0x06, new Uint8Array([first, ...rest]));
}
/** Context-specific primitive: `[n] IMPLICIT OCTET STRING`. */
function derImplicitOctetString(tag: number, content: Uint8Array): Uint8Array {
    return derTagged(0x80 | tag, content);
}
/**
 * Context-specific explicit wrapper: `[n] EXPLICIT content`.
 *
 * The content is wrapped as-is (not re-sequenced), so callers control whether
 * the payload is a bare INTEGER (version `[0]`) or a SEQUENCE (extensions
 * `[3]`).
 */
function derExplicitTagged(tag: number, content: Uint8Array): Uint8Array {
    return derTagged(0xa0 | tag, content);
}

// --- OIDs (avoid magic strings) ----------------------------------------

const OID = {
    ecdsaWithSHA256: "1.2.840.10045.4.3.2",
    commonName: "2.5.4.3",
    subjectAltName: "2.5.29.17",
    keyUsage: "2.5.29.15",
    basicConstraints: "2.5.29.19",
} as const;

/** Format a Date as a DER GeneralizedTime string: `YYYYMMDDHHMMSSZ`. */
function toGeneralizedTime(d: Date): string {
    return d.toISOString().replace(/[-:T]/g, "").slice(0, 14) + "Z";
}

/**
 * Generate a self-signed ECDSA P-256 certificate valid for the given SANs.
 *
 * @param dnsNames DNS SANs (e.g. `["localhost"]`).
 * @param ipAddresses IP SANs in dotted-quad form (e.g. `["127.0.0.1"]`).
 * @param validityDays Leaf validity window (default 1 day — sink certs are
 *   throwaway).
 */
export function generateSelfSignedCert(
    dnsNames: readonly string[] = ["localhost"],
    ipAddresses: readonly string[] = ["127.0.0.1"],
    validityDays = 1,
): SelfSignedCert {
    const { publicKey, privateKey } = generateKeyPairSync("ec", {
        namedCurve: "P-256",
        publicKeyEncoding: { type: "spki", format: "der" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const spki = new Uint8Array(publicKey);

    const notBefore = new Date();
    const notAfter = new Date(notBefore.getTime() + validityDays * 24 * 60 * 60 * 1000);

    // Subject / issuer: CN=localhost (self-signed ⇒ issuer === subject).
    const cnValue = derUtf8String(new TextEncoder().encode("localhost"));
    const name = derSequence(derSet(derSequence(derOid(OID.commonName), cnValue)));

    // SubjectAlternativeName entries: [2] DNS name, [7] raw IP bytes.
    const sanEntries: Uint8Array[] = [];
    for (const dns of dnsNames) {
        sanEntries.push(derImplicitOctetString(2, new TextEncoder().encode(dns)));
    }
    for (const ip of ipAddresses) {
        const bytes = ip.split(".").map((o) => Number.parseInt(o, 10));
        sanEntries.push(derImplicitOctetString(7, new Uint8Array(bytes)));
    }
    const sanExt = derSequence(
        derOid(OID.subjectAltName),
        derOctetString(derSequence(...sanEntries)),
    );

    // KeyUsage: digitalSignature (bit 0) — critical.
    const kuExt = derSequence(
        derOid(OID.keyUsage),
        derBooleanTrue(),
        derOctetString(new Uint8Array([0x03, 0x02, 0x07, 0x80])),
    );

    // BasicConstraints: CA=false — critical.
    const bcExt = derSequence(
        derOid(OID.basicConstraints),
        derBooleanTrue(),
        derOctetString(derSequence()),
    );

    const serial = derInteger(new Uint8Array([0x01]));
    const sigAlg = derSequence(derOid(OID.ecdsaWithSHA256), derNull());
    const validity = derSequence(
        derGeneralizedTime(toGeneralizedTime(notBefore)),
        derGeneralizedTime(toGeneralizedTime(notAfter)),
    );

    const tbs = derSequence(
        derExplicitTagged(0, derInteger(new Uint8Array([0x02]))), // [0] version = v3
        serial,
        sigAlg,
        name,
        validity,
        name,
        spki,
        derExplicitTagged(3, derSequence(sanExt, kuExt, bcExt)), // [3] extensions
    );

    // Self-sign with SHA256 over the TBS DER.
    const signer = createSign("SHA256");
    signer.update(Buffer.from(tbs));
    const signature = new Uint8Array(signer.sign({ key: privateKey, dsaEncoding: "der" }));

    const certDer = derSequence(concatBytes(tbs, sigAlg, derBitString(signature)));
    return { certDer, keyPem: privateKey as string };
}
