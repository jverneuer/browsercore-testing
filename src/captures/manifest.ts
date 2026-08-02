/**
 * In-repo golden capture manifest (lives under src/ so it is in rootDir).
 *
 * Single source of truth for which captures exist on disk. Each entry pairs
 * its typed {@link CaptureMeta} with the raw bytes read from the sibling
 * `.bin` in the package-level `captures/` directory. Tests and reference
 * providers discover captures through this array rather than hard-coding paths
 * (no magic strings — see CODING_STANDARDS.md).
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import type { ProfileId } from "@network/profiles";
import type { CaptureMeta } from "../types.js";

const here = dirname(fileURLToPath(import.meta.url));
// src/captures -> package root -> captures/
const capturesDir = join(here, "..", "..", "captures");

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
    const abs = join(capturesDir, relativePath);
    return {
        path: relativePath,
        meta,
        bytes: readFileSync(abs),
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
];
