/**
 * JA3 / JA4 TLS fingerprinting (docs/TEST-SUITE.md, Category 4).
 *
 * JA3 (https://github.com/salesforce/ja3) hashes the decimal representation of
 * a ClientHello's selectable fields. Format string:
 *
 *   SSLVersion,CipherSuites,Extensions,SupportedGroups,EllipticCurvePointFormats
 *
 * each field is a dash-joined list of integers; the whole string is MD5-hashed
 * to produce the JA3 digest. This implementation parses the ClientHello out of
 * its TLS record wrapper.
 */

import { createHash } from "node:crypto";

/** Reasons a ClientHello cannot be parsed into a JA3 input. */
export class Ja3ParseError extends Error {
    public readonly kind = "Ja3ParseError" as const;
    constructor(message: string) {
        super(message);
        this.name = "Ja3ParseError";
    }
}

/** Read a big-endian uint16 at `offset` in `buf`. */
function uint16(buf: Uint8Array, offset: number): number {
    return (buf[offset]! << 8) | buf[offset + 1]!;
}

/**
 * Parse a TLS ClientHello from a TLS record (or handshake) buffer and return
 * the dash-jojoined JA3 input segments plus the final MD5 digest.
 *
 * Accepts either a full TLS record (record type 0x16) or a bare handshake
 * (handshake type 0x01).
 */
export function computeJa3(clientHello: Uint8Array): string {
    const s = parseClientHello(clientHello);
    const ja3String = [s.version, s.ciphers, s.extensions, s.supportedGroups, s.ecPointFormats].join(
        ",",
    );
    return createHash("md5").update(ja3String).digest("hex");
}

/** JA3 input segments (for inspection/testing). */
export interface Ja3Segments {
    readonly version: string;
    readonly ciphers: string;
    readonly extensions: string;
    readonly supportedGroups: string;
    readonly ecPointFormats: string;
}

/** Parse a ClientHello into its five JA3 segments. */
export function parseClientHello(clientHello: Uint8Array): Ja3Segments {
    let pos: number;
    let handshakeLen: number;

    // Detect TLS record wrapper (ContentType handshake = 0x16).
    if (clientHello[0] === 0x16) {
        if (clientHello.length < 5) {
            throw new Ja3ParseError("TLS record too short");
        }
        // offset 3..4 = record length; handshake starts at 5
        pos = 5;
        if (clientHello[pos] !== 0x01) {
            throw new Ja3ParseError(`Expected ClientHello (0x01) at record+0, got 0x${clientHello[pos]?.toString(16)}`);
        }
        handshakeLen = readInt24(clientHello, pos + 1);
        pos += 4; // handshake type(1) + length(3)
        const available = clientHello.length - pos;
        if (handshakeLen > available) {
            throw new Ja3ParseError(`Handshake length ${handshakeLen} exceeds available ${available} bytes`);
        }
    } else if (clientHello[0] === 0x01) {
        handshakeLen = readInt24(clientHello, 1);
        pos = 4;
        const available = clientHello.length - pos;
        if (handshakeLen > available) {
            throw new Ja3ParseError(`Handshake length ${handshakeLen} exceeds available ${available} bytes`);
        }
    } else {
        throw new Ja3ParseError(`Not a TLS record or ClientHello (first byte 0x${clientHello[0]?.toString(16)})`);
    }

    const end = pos + handshakeLen;

    // client_version(2)
    const version = uint16(clientHello, pos);
    pos += 2;
    // random(32)
    pos += 32;
    // session_id(variable)
    const sessionIdLen = clientHello[pos]!;
    pos += 1 + sessionIdLen;
    // cipher_suites(variable)
    const cipherSuitesLen = uint16(clientHello, pos);
    pos += 2;
    const ciphers = readUint16List(clientHello, pos, cipherSuitesLen);
    pos += cipherSuitesLen;
    // compression_methods(variable)
    const compLen = clientHello[pos]!;
    pos += 1 + compLen;
    // extensions(variable)
    if (pos + 2 > end) {
        // No extensions present.
        return {
            version: String(version),
            ciphers: ciphers.join("-"),
            extensions: "",
            supportedGroups: "",
            ecPointFormats: "",
        };
    }
    const extensionsLen = uint16(clientHello, pos);
    pos += 2;
    const extensionsEnd = pos + extensionsLen;

    const extensionTypes: number[] = [];
    const supportedGroups: number[] = [];
    const ecPointFormats: number[] = [];

    while (pos + 4 <= extensionsEnd) {
        const extType = uint16(clientHello, pos);
        const extLen = uint16(clientHello, pos + 2);
        pos += 4;
        extensionTypes.push(extType);

        if (extType === 0x000a && extLen >= 4) {
            // supported_groups(10): list of uint16 group ids
            const listLen = uint16(clientHello, pos);
            supportedGroups.push(...readUint16List(clientHello, pos + 2, listLen));
        } else if (extType === 0x000b && extLen >= 1) {
            // ec_point_formats(11): list of uint8 formats
            const listLen = clientHello[pos]!;
            for (let i = 0; i < listLen; i++) {
                ecPointFormats.push(clientHello[pos + 1 + i]!);
            }
        }

        pos += extLen;
    }

    return {
        version: String(version),
        ciphers: ciphers.join("-"),
        extensions: extensionTypes.join("-"),
        supportedGroups: supportedGroups.join("-"),
        ecPointFormats: ecPointFormats.join("-"),
    };
}

function readInt24(buf: Uint8Array, offset: number): number {
    return (buf[offset]! << 16) | (buf[offset + 1]! << 8) | buf[offset + 2]!;
}

function readUint16List(buf: Uint8Array, offset: number, byteLen: number): number[] {
    const out: number[] = [];
    for (let i = 0; i + 1 < byteLen; i += 2) {
        out.push((buf[offset + i]! << 8) | buf[offset + i + 1]!);
    }
    return out;
}
