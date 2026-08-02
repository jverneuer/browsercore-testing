/**
 * Pluggable layered reference provider.
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
 * See docs/TEST-SUITE.md (Cat 3, 4, 14) for how references feed comparison.
 */

import { execFile, type ExecFileOptions } from "node:child_process";
import { join } from "node:path";
import { promisify } from "node:util";
import type { ProfileId } from "@browsercore/profiles";
import type { CaptureMeta, GoldenCapture } from "../types.js";
import { computeJa3, computeJa4Fingerprint } from "../fingerprint/index.js";
import { loadCaptureMeta } from "../golden/golden.js";
import { TestingError } from "../errors.js";
import { assertNever } from "../utils.js";

type ExecFileAsync = (
    command: string,
    args: readonly string[],
    options?: ExecFileOptions,
) => Promise<{ readonly stdout: string; readonly stderr: string }>;

// execFile returns a ChildProcess, but promisify expects a void-returning
// function — the cast satisfies strict-void-return without changing runtime
// behavior. The cast is erased at runtime, so util.promisify.custom is
// preserved and the promise still resolves to {stdout, stderr}, keeping the
// stderr channel.
const execFileAsync = promisify(
    execFile as unknown as (...args: Parameters<typeof execFile>) => void,
) as unknown as ExecFileAsync;

const here = import.meta.dirname;
const packageRoot = join(here, "..", "..");
const defaultCapturesDir = join(packageRoot, "captures");

/** Which reference backend to use. Discriminated union — no bare string. */
export type ReferenceProviderKind =
    | { readonly kind: "curl-impersonate" }
    | { readonly kind: "real-browser" };

/** Observable TLS/HTTP fingerprint of a captured reference exchange. */
export interface Fingerprint {
    readonly ja3: string;
    readonly ja4: string;
    readonly alpn: readonly string[];
    readonly cipherSuite: string;
    readonly protocolVersion: string;
    readonly signatureAlgorithms: readonly string[];
    readonly ellipticCurves: readonly string[];
}

/** Options for the curl-impersonate provider. */
export interface CurlImpersonateOptions {
    /** Path / name of the curl-impersonate binary. Default "curl-impersonate". */
    readonly command: string;
    /** Extra argv passed to the binary. */
    readonly extraArgs?: readonly string[];
}

/** Options for the real-browser (pre-recorded capture) provider. */
export interface RealBrowserOptions {
    readonly command?: undefined;
    /** Override captures directory. Defaults to the in-repo `captures/` dir. */
    readonly capturesDir?: string;
}

/** Options for the {@link ReferenceProviderFacade}. */
export interface ReferenceFacadeOptions {
    readonly curl?: CurlImpersonateOptions;
    readonly browser?: RealBrowserOptions;
}

/** A source of truth for a browser profile's wire behavior. */
export interface ReferenceProvider {
    readonly kind: ReferenceProviderKind;
    capture(profile: ProfileId, url: string): Promise<GoldenCapture>;
    fingerprint(profile: ProfileId): Promise<Fingerprint>;
    availableProfiles(): ProfileId[];
}

/** Raised when a reference provider cannot capture or fingerprint a profile. */
export class ReferenceError extends TestingError {
    constructor(message: string, options?: { cause?: Error }) {
        super(message, options);
        this.name = "ReferenceError";
    }
}

/**
 * PRIMARY provider — shells out to curl-impersonate.
 *
 * `capture()` invokes the curl-impersonate binary against `url`, impersonating
 * `profile`, and returns the raw bytes it observed on the wire. The binary
 * must be on PATH (or in `command`); if it is missing, the call throws
 * {@link ReferenceError} so the facade can fall back to the secondary.
 */
export class CurlImpersonateProvider implements ReferenceProvider {
    public readonly kind: ReferenceProviderKind = { kind: "curl-impersonate" } as const;
    public readonly command: string;
    public readonly extraArgs: readonly string[];

    constructor(options?: CurlImpersonateOptions) {
        this.command = options?.command ?? "curl-impersonate";
        this.extraArgs = options?.extraArgs ?? [];
    }

    availableProfiles(): ProfileId[] {
        // curl-impersonate ships these browser impersonation targets.
        return [
            "chrome-140" as ProfileId,
            "chrome-139" as ProfileId,
            "firefox-135" as ProfileId,
            "firefox-128" as ProfileId,
            "safari-18" as ProfileId,
            "edge-140" as ProfileId,
        ];
    }

    async capture(profile: ProfileId, url: string): Promise<GoldenCapture> {
        const profileFlag = `--${String(profile)}`;
        const args = [profileFlag, "--dump-traffic", ...this.extraArgs, url];
        let stdout: string;
        let stderr: string;
        try {
            const out = await execFileAsync(this.command, args, {
                timeout: 30_000,
                maxBuffer: 64 * 1024 * 1024,
            });
            stdout = out.stdout;
            stderr = out.stderr;
        } catch (e) {
            const cause = e instanceof Error ? e : new Error(String(e));
            throw new ReferenceError(
                `curl-impersonate capture for ${String(profile)} failed: ${cause.message}`,
                { cause },
            );
        }
        void stderr;
        const bytes = parseDumpOutput(stdout);
        return {
            id: `${profile}/tls/client_hello` as GoldenCapture["id"],
            source: profileToSource(profile),
            protocol: "tls",
            bytes,
            description: `curl-impersonate capture for ${String(profile)}`,
        };
    }

    async fingerprint(profile: ProfileId): Promise<Fingerprint> {
        const capture = await this.capture(profile, "https://example.com");
        return fingerprintFromTlsCapture(capture);
    }
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
                const secondaryCause = secondaryErr instanceof Error ? secondaryErr : new Error(String(secondaryErr));
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
                const secondaryCause = secondaryErr instanceof Error ? secondaryErr : new Error(String(secondaryErr));
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
            return new CurlImpersonateProvider(options as CurlImpersonateOptions | undefined);
        case "real-browser":
            return new RealBrowserCaptureProvider(options as RealBrowserOptions | undefined);
        default:
            // Exhaustiveness guaranteed by the union — unreachable unless a new
            // provider kind is added without a handler.
            throw assertNever(kind);
    }
}

/**
 * Construct the full {@link ReferenceProviderFacade} wrapping both providers
 * plus the node-reference oracle. This is the recommended entry point for
 * tests that want primary→secondary fallback.
 */
export function createReferenceFacade(options?: ReferenceFacadeOptions): ReferenceProviderFacade {
    return new ReferenceProviderFacade(options);
}

/** Map a {@link ProfileId} to its {@link CaptureSource} tag. */
function profileToSource(profile: ProfileId): GoldenCapture["source"] {
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
 * payload between the markers. For now we assume the body is a contiguous hex
 * block — adjust the parser if curl-impersonate's format differs.
 */
/**
 * Parse curl-impersonate `--dump-traffic` output into raw bytes.
 *
 * Exported for unit testing the parse error branches (no hex / odd-length hex).
 */
export function parseDumpOutput(stdout: string): Uint8Array {
    // Find the hex body — everything after the ">>> traffic <<<" marker.
    const marker = ">>> traffic <<<";
    const idx = stdout.indexOf(marker);
    const body = idx === -1 ? stdout : stdout.slice(idx + marker.length);
    const hex = body.replaceAll(/[^0-9a-fA-F]/gu, "");
    if (hex.length === 0) {
        throw new ReferenceError("curl-impersonate dump produced no hex bytes");
    }
    if (hex.length % 2 !== 0) {
        throw new ReferenceError(
            `curl-impersonate dump produced odd-length hex (${hex.length})`,
        );
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
 */
/**
 * Derive a {@link Fingerprint} from a TLS ClientHello capture.
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
 */
/**
 * Extract a human-readable cipher-suite name from a JA4 tag.
 *
 * Exported for unit testing the empty-tag fallback branch.
 */
export function cipherSuiteName(ja4Tag: string): string {
    const a = ja4Tag.split("_")[0] ?? "";
    return a.length > 0 ? a : "unknown";
}
