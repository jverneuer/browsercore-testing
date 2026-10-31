/**
 * In-repo golden capture manifest (lives under src/ so it is in rootDir).
 *
 * Single source of truth for which captures exist on disk. Each entry pairs
 * its typed {@link CaptureMeta} with the raw bytes read from the sibling
 * `.bin` in the package-level `captures/` directory. Tests and reference
 * providers discover captures through this array rather than hard-coding paths
 * (no magic strings — see CODING_STANDARDS.md).
 */

import type { ProfileId } from "@browsercore/profiles";
import type { CaptureMeta } from "../types.js";
import { createFileSystem, createPath } from "../node-provider.js";

const fileSystem = createFileSystem();
const path = createPath();

const here = import.meta.dirname;
// src/captures -> package root -> captures/
const capturesDir = path.join(here, "..", "..", "captures");

/** A discovered capture: its typed metadata plus the raw on-disk bytes. */
export interface CaptureEntry {
    readonly path: string;
    readonly meta: CaptureMeta;
    readonly bytes: Uint8Array;
}

function id(s: string): ProfileId {
    return s as ProfileId;
}

function entry(relativePath: string, meta: CaptureMeta): CaptureEntry {
    const abs = path.join(capturesDir, relativePath);
    return {
        path: relativePath,
        meta,
        bytes: fileSystem.readFileSync(abs),
    };
}

export const captures: readonly CaptureEntry[] = [
    entry(
        "chrome-140/tls/client_hello.bin",
        {
            source: "curl-impersonate",
            profile: id("chrome-140"),
            protocol: "tls",
            record: "client_hello",
            description:
                "TLS 1.3 ClientHello from curl-impersonate --chrome-140.",
            randomizedFields: [
                { byteOffset: 12, length: 32, reason: "random" },
                { byteOffset: 49, length: 32, reason: "ephemeral_key" },
            ],
            createdAt: "2026-08-02T00:00:00Z",
        },
    ),
    entry(
        "chrome-140/http2/settings.bin",
        {
            source: "curl-impersonate",
            profile: id("chrome-140"),
            protocol: "http2",
            record: "settings",
            description:
                "First HTTP/2 SETTINGS frame from curl-impersonate --chrome-140.",
            randomizedFields: [],
            createdAt: "2026-08-02T00:00:00Z",
        },
    ),
    entry(
        "firefox-128/tls/client_hello.bin",
        {
            source: "curl-impersonate",
            profile: id("firefox-128"),
            protocol: "tls",
            record: "client_hello",
            description:
                "TLS 1.3 ClientHello from curl-impersonate --firefox-128.",
            randomizedFields: [
                { byteOffset: 12, length: 32, reason: "random" },
                { byteOffset: 49, length: 32, reason: "ephemeral_key" },
            ],
            createdAt: "2026-08-02T00:00:00Z",
        },
    ),
    // ── REAL wire captures (curl-impersonate, oracle-verified) ──────────────
    // Byte-for-byte real ClientHellos with oracle-verified fingerprints
    // (tls.peet.ws/api/all reference JSONs sit beside each capture). Unlike
    // the synthetic stubs above, these are what golden comparisons should
    // run against. Registered 0.2.5 — they existed on disk since August but
    // loadCaptures() never surfaced them.
    entry(
        "chrome-131/tls/client_hello.bin",
        {
            source: "curl-impersonate",
            profile: id("chrome-131"),
            protocol: "tls",
            record: "client_hello",
            description:
                "REAL chrome-131 ClientHello (1753B) via curl-impersonate against tls.peet.ws. Oracle gold: ja4 t13d1516h2_8daaf6152771_02713d6af862, ja3_hash fb519300321e7e157792ac8d3a77e9ee.",
            randomizedFields: [
                { byteOffset: 12, length: 32, reason: "random" },
                { byteOffset: 112, length: 1641, reason: "grease" },
            ],
            createdAt: "2026-08-04T00:28:49Z",
        },
    ),
    entry(
        "firefox-133/tls/client_hello.bin",
        {
            source: "curl-impersonate",
            profile: id("firefox-133"),
            protocol: "tls",
            record: "client_hello",
            description:
                "REAL firefox-133 ClientHello via curl-impersonate. Oracle gold: ja4 t13d1716h2_5b57614c22b0_eeeea6562960, ja3_hash 2d692a4485ca2f5f2b10ecb2d2909ad3.",
            randomizedFields: [
                { byteOffset: 12, length: 32, reason: "random" },
            ],
            createdAt: "2026-08-04T00:00:00Z",
        },
    ),
    entry(
        "safari-17/tls/client_hello.bin",
        {
            source: "curl-impersonate",
            profile: id("safari-17"),
            protocol: "tls",
            record: "client_hello",
            description:
                "REAL safari-17 ClientHello via curl-impersonate. Oracle gold: ja4 t13d2014h2_a09f3c656075_874d27d7ca63, ja3_hash 773906b0efdefa24a7f2b8eb6985bf37.",
            randomizedFields: [
                { byteOffset: 12, length: 32, reason: "random" },
            ],
            createdAt: "2026-08-04T00:00:00Z",
        },
    ),
];
