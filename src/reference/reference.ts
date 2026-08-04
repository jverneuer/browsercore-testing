/**
 * Pluggable layered reference provider — facade + factory.
 *
 * The reference implementation is the source of truth for what a given browser
 * profile SHOULD produce on the wire. Three backends are wrapped behind one
 * facade:
 *
 * - `node-reference` (oracle) — Node's built-in crypto/dns/zlib/http
 *   implementations, used as the spec oracle for primitive layers where Node IS
 *   the reference (see `node-reference.ts`).
 * - `curl-impersonate` (PRIMARY) — fast CI path; shells out to the
 *   curl-impersonate binary to capture real traffic for a profile.
 * - `real-browser` (SECONDARY) — loads pre-recorded captures from the
 *   `captures/` directory, recorded from an actual browser.
 *
 * The {@link ReferenceProviderFacade} ties them together: capture resolves via
 * primary then secondary; fingerprint is derived from the captured bytes; the
 * node-reference oracle is exposed for primitive-layer comparisons.
 *
 * The providers and dump helpers live in their own modules; this file owns the
 * facade + factory dispatch. See docs/TEST-SUITE.md (Cat 3, 4, 14).
 */

import type { ProfileId } from "@browsercore/profiles";
import type { GoldenCapture } from "../types.js";
import type {
    Fingerprint,
    ReferenceProvider,
    ReferenceProviderKind,
} from "./reference-types.js";
import { CurlImpersonateProvider, type CurlImpersonateOptions } from "./curl-provider.js";
import { RealBrowserCaptureProvider, type RealBrowserOptions } from "./browser-provider.js";
import { ReferenceError } from "./reference-errors.js";
import { assertNever } from "../utils.js";

// Re-export so existing import sites (`from "./reference.js"`) keep resolving
// after the providers and helpers moved into focused modules.
export { CurlImpersonateProvider } from "./curl-provider.js";
export type { CurlImpersonateOptions } from "./curl-provider.js";
export { RealBrowserCaptureProvider } from "./browser-provider.js";
export type { RealBrowserOptions } from "./browser-provider.js";
export { ReferenceError, DumpParseError } from "./reference-errors.js";
export type { DumpParseKind } from "./reference-errors.js";
export { parseDumpOutput, fingerprintFromTlsCapture, cipherSuiteName } from "./dump.js";
export type {
    Fingerprint,
    ReferenceProvider,
    ReferenceProviderKind,
} from "./reference-types.js";

/** Options for the {@link ReferenceProviderFacade}. */
export interface ReferenceFacadeOptions {
    readonly curl?: CurlImpersonateOptions;
    readonly browser?: RealBrowserOptions;
}

/**
 * Facade wrapping the node-reference oracle + primary (curl-impersonate) and
 * secondary (real-browser) providers behind a single {@link ReferenceProvider}.
 *
 * `capture()` tries the primary first; if it fails (binary missing, network
 * error, ...) it falls back to the secondary's pre-recorded captures. The
 * node-reference oracle is exposed via {@link ReferenceProviderFacade.nodeOracle}
 * for primitive-layer comparisons (crypto, dns, zlib, wire format) — those
 * layers are NOT fingerprinted here; they live in `node-reference.ts`.
 */
export class ReferenceProviderFacade implements ReferenceProvider {
    public readonly kind: ReferenceProviderKind = { kind: "curl-impersonate" } as const;
    private readonly primary: CurlImpersonateProvider;
    private readonly secondary: RealBrowserCaptureProvider;

    constructor(options?: ReferenceFacadeOptions) {
        this.primary = new CurlImpersonateProvider(options?.curl);
        this.secondary = new RealBrowserCaptureProvider(options?.browser);
    }

    /**
     * Node-reference oracle — the spec oracle for primitive layers where Node
     * IS the reference (crypto, dns, zlib, wire format). NOT used for
     * browser-fingerprint comparison; that is what the providers are for.
     */
    get nodeOracle(): typeof nodeOracle {
        return nodeOracle;
    }

    availableProfiles(): ProfileId[] {
        // Union of profiles from both providers, de-duplicated.
        const seen = new Set<string>();
        const out: ProfileId[] = [];
        for (const p of [...this.primary.availableProfiles(), ...this.secondary.availableProfiles()]) {
            const key = String(p);
            if (seen.has(key)) {
                continue;
            }
            seen.add(key);
            out.push(p);
        }
        return out;
    }

    async capture(profile: ProfileId, url: string): Promise<GoldenCapture> {
        try {
            return await this.primary.capture(profile, url);
        } catch (primaryErr) {
            const cause = primaryErr instanceof Error ? primaryErr : new Error(String(primaryErr));
            // Fall back to the secondary provider's pre-recorded captures.
            try {
                return await this.secondary.capture(profile, url);
            } catch (secondaryErr) {
                const secondaryCause =
                    secondaryErr instanceof Error ? secondaryErr : new Error(String(secondaryErr));
                throw new ReferenceError(
                    `No reference available for ${String(profile)}: primary failed (${cause.message}), secondary failed (${secondaryCause.message})`,
                    { cause: secondaryCause },
                );
            }
        }
    }

    async fingerprint(profile: ProfileId): Promise<Fingerprint> {
        try {
            return await this.primary.fingerprint(profile);
        } catch (primaryErr) {
            const cause = primaryErr instanceof Error ? primaryErr : new Error(String(primaryErr));
            try {
                return await this.secondary.fingerprint(profile);
            } catch (secondaryErr) {
                const secondaryCause =
                    secondaryErr instanceof Error ? secondaryErr : new Error(String(secondaryErr));
                throw new ReferenceError(
                    `No fingerprint available for ${String(profile)}: primary failed (${cause.message}), secondary failed (${secondaryCause.message})`,
                    { cause: secondaryCause },
                );
            }
        }
    }
}

/**
 * Node-reference oracle re-export — the spec oracle for primitive layers.
 *
 * Imported lazily so the facade type references resolve without a cycle.
 */
import * as nodeOracle from "./node-reference.js";

/** Construct the {@link ReferenceProvider} matching {@link ReferenceProviderKind}. */
export function createReferenceProvider(
    kind: ReferenceProviderKind,
    options?: CurlImpersonateOptions | RealBrowserOptions,
): ReferenceProvider {
    switch (kind.kind) {
        case "curl-impersonate":
            return new CurlImpersonateProvider(toCurlOptions(options));
        case "real-browser":
            return new RealBrowserCaptureProvider(toBrowserOptions(options));
        default:
            // Exhaustiveness guaranteed by the union — unreachable unless a new
            // provider kind is added without a handler.
            return assertNever(kind);
    }
}

/**
 * Narrow the shared options union to the curl-impersonate shape.
 *
 * Copies only the fields the curl provider reads, so passing a
 * browser-options object does not leak `capturesDir` into a place that ignores
 * it. No `as` cast: the result is built field-by-field from validated reads.
 */
function toCurlOptions(
    options: CurlImpersonateOptions | RealBrowserOptions | undefined,
): CurlImpersonateOptions | undefined {
    if (options === undefined || !("command" in options) || options.command === undefined) {
        return undefined;
    }
    return options.extraArgs === undefined
        ? { command: options.command }
        : { command: options.command, extraArgs: options.extraArgs };
}

/**
 * Narrow the shared options union to the real-browser shape.
 *
 * Copies only the fields the browser provider reads. `command` is `undefined`
 * on `RealBrowserOptions` by construction, so it is not copied.
 */
function toBrowserOptions(
    options: CurlImpersonateOptions | RealBrowserOptions | undefined,
): RealBrowserOptions | undefined {
    if (options === undefined || !("capturesDir" in options) || options.capturesDir === undefined) {
        return undefined;
    }
    return { capturesDir: options.capturesDir };
}

/**
 * Construct the full {@link ReferenceProviderFacade} wrapping both providers
 * plus the node-reference oracle. This is the recommended entry point for
 * tests that want primary→secondary fallback.
 */
export function createReferenceFacade(options?: ReferenceFacadeOptions): ReferenceProviderFacade {
    return new ReferenceProviderFacade(options);
}
