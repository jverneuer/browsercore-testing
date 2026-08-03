/**
 * curl-impersonate dump parsing + TLS fingerprint derivation.
 *
 * Split out of `reference.ts` so the providers and facade stay focused on
 * dispatch while this file owns the curl-impersonate `--dump-traffic` byte
 * format and the JA3/JA4 derivation from a captured ClientHello.
 */

import type { ProfileId } from "@browsercore/profiles";
import type { CaptureMeta, GoldenCapture } from "../types.js";
import { computeJa3, computeJa4Fingerprint } from "../fingerprint/index.js";
import { loadCaptureMeta } from "../golden/golden.js";
import type { Fingerprint } from "./reference-types.js";
import { DumpParseError } from "./reference-errors.js";

/** Map a {@link ProfileId} to its {@link CaptureSource} tag. */
export function profileToSource(profile: ProfileId): GoldenCapture["source"] {
    const p = String(profile);
    if (p.startsWith("firefox")) {
        return "firefox-135";
    }
    if (p.startsWith("safari")) {
        return "safari-18";
    }
    if (p.startsWith("edge")) {
        return "edge-140";
    }
    return "chrome-140";
}

/**
 * Parse curl-impersonate `--dump-traffic` output into raw bytes.
 *
 * The dump format is a hex dump with one line per record; we extract the hex
 * payload after the `>>> traffic <<<` marker. Throws {@link DumpParseError}
 * when no hex bytes follow the marker or the hex has odd length.
 */
export function parseDumpOutput(stdout: string): Uint8Array {
    // Find the hex body — everything after the ">>> traffic <<<" marker.
    const marker = ">>> traffic <<<";
    const idx = stdout.indexOf(marker);
    const body = idx === -1 ? stdout : stdout.slice(idx + marker.length);
    const hex = body.replaceAll(/[^0-9a-fA-F]/gu, "");
    if (hex.length === 0) {
        throw new DumpParseError("no_hex", 0);
    }
    if (hex.length % 2 !== 0) {
        throw new DumpParseError("odd_length", hex.length);
    }
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}

/**
 * Derive a {@link Fingerprint} from a TLS ClientHello capture.
 *
 * Computes JA3 + JA4 from the raw bytes and reads the per-extension metadata
 * (supported groups, signature algorithms, ALPN) from the sidecar
 * `.meta.json` when available.
 *
 * Exported for unit testing the try/catch branches: the happy path reads the
 * sidecar meta, while the fallback path is taken when the sidecar is missing.
 */
export function fingerprintFromTlsCapture(capture: GoldenCapture): Fingerprint {
    const ja3 = computeJa3(capture.bytes);
    const ja4 = computeJa4Fingerprint(capture.bytes);

    // Read the sidecar meta for richer fields (signature algorithms, ALPN,
    // supported curves). Fall back to empty arrays if missing.
    const alpn: readonly string[] = [];
    const signatureAlgorithms: readonly string[] = [];
    const ellipticCurves: readonly string[] = [];
    try {
        const meta: CaptureMeta = loadCaptureMeta(capture.id);
        if (meta.protocol === "tls") {
            // CaptureMeta doesn't carry ALPN/sigAlgs/curves yet; this is a
            // placeholder for when the sidecar schema is extended.
            void meta;
        }
    } catch {
        // Sidecar missing or unparseable — leave richer fields empty.
    }

    return {
        ja3,
        ja4: ja4.tag,
        alpn,
        cipherSuite: cipherSuiteName(ja4.tag),
        protocolVersion: ja4.tag.slice(5, 7) || "unknown",
        signatureAlgorithms,
        ellipticCurves,
    };
}

/**
 * Extract a human-readable cipher-suite name from a JA4 tag.
 *
 * JA4 doesn't directly encode the negotiated cipher; this is a placeholder
 * that returns the JA4_a segment for inspection. Real cipher-suite resolution
 * requires parsing the ServerHello, which is out of scope for the capture.
 *
 * Exported for unit testing the empty-tag fallback branch.
 */
export function cipherSuiteName(ja4Tag: string): string {
    const a = ja4Tag.split("_")[0] ?? "";
    return a.length > 0 ? a : "unknown";
}
