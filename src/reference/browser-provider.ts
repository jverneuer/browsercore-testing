/**
 * SECONDARY reference provider — loads pre-recorded captures from `captures/`.
 *
 * `capture()` resolves a stored capture for the profile; `fingerprint()`
 * derives a {@link Fingerprint} from the captured bytes (only TLS ClientHellos
 * are fingerprinted — other protocols throw). Split out of `reference.ts` so
 * the facade stays focused on primary → secondary dispatch.
 */

import type { ProfileId } from "@browsercore/profiles";
import type { GoldenCapture } from "../types.js";
import type { Fingerprint, ReferenceProvider, ReferenceProviderKind } from "./reference-types.js";
import { ReferenceError } from "./reference-errors.js";
import { fingerprintFromTlsCapture, profileToSource } from "./dump.js";

/** Options for the real-browser (pre-recorded capture) provider. */
export interface RealBrowserOptions {
    readonly command?: undefined;
    /** Override captures directory. Defaults to the in-repo `captures/` dir. */
    readonly capturesDir?: string;
}

/**
 * SECONDARY provider — loads pre-recorded captures from the `captures/` dir.
 *
 * `capture()` resolves a stored capture for the profile; `fingerprint()`
 * derives a {@link Fingerprint} from the captured bytes (only TLS
 * ClientHellos are fingerprinted — other protocols return a stub).
 */
export class RealBrowserCaptureProvider implements ReferenceProvider {
    public readonly kind: ReferenceProviderKind = { kind: "real-browser" } as const;
    public readonly capturesDir: string;

    constructor(options?: RealBrowserOptions) {
        this.capturesDir = options?.capturesDir ?? defaultCapturesDir;
    }

    availableProfiles(): ProfileId[] {
        // Discovery is driven by the captures manifest (captures/manifest.ts).
        return [
            "chrome-140" as ProfileId,
            "firefox-128" as ProfileId,
        ];
    }

    async capture(profile: ProfileId, _url: string): Promise<GoldenCapture> {
        void _url;
        const manifest = await import("../captures/manifest.js");
        const entry = manifest.captures.find((c) => c.meta.profile === profile);
        if (entry === undefined) {
            throw new ReferenceError(
                `No pre-recorded capture for profile ${String(profile)}`,
            );
        }
        return {
            id: `${profile}/tls/client_hello` as GoldenCapture["id"],
            source: profileToSource(profile),
            protocol: entry.meta.protocol,
            bytes: entry.bytes,
            description: entry.meta.description,
        };
    }

    async fingerprint(profile: ProfileId): Promise<Fingerprint> {
        const capture = await this.capture(profile, "https://example.com");
        if (capture.protocol !== "tls") {
            throw new ReferenceError(
                `fingerprint() only supports TLS captures; got ${capture.protocol}`,
            );
        }
        return fingerprintFromTlsCapture(capture);
    }
}

// Default captures dir resolved from this module's location. Computed at module
// load (not per-instance) since import.meta.dirname is static.
import { join } from "node:path";
const here = import.meta.dirname;
const packageRoot = join(here, "..", "..");
const defaultCapturesDir = join(packageRoot, "captures");
