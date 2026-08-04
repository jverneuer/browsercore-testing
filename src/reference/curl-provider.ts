/**
 * PRIMARY reference provider — shells out to curl-impersonate.
 *
 * `capture()` invokes the curl-impersonate binary against `url`, impersonating
 * `profile`, and returns the raw bytes it observed on the wire. The binary
 * must be on PATH (or in `command`); if it is missing, the call throws
 * {@link ReferenceError} so the facade can fall back to the secondary.
 *
 * Split out of `reference.ts` so the facade module stays focused on primary →
 * secondary dispatch while this file owns the curl-impersonate subprocess
 * wiring and dump-format parsing.
 */

import {
    execFile,
    type ExecException,
    type ExecFileOptionsWithStringEncoding,
} from "node:child_process";
import type { ProfileId } from "@browsercore/profiles";
import type { GoldenCapture } from "../types.js";
import type { Fingerprint, ReferenceProvider, ReferenceProviderKind } from "./reference-types.js";
import { ReferenceError } from "./reference-errors.js";
import { fingerprintFromTlsCapture, parseDumpOutput, profileToSource } from "./dump.js";

/** Options for the curl-impersonate provider. */
export interface CurlImpersonateOptions {
    /** Path / name of the curl-impersonate binary. Default "curl-impersonate". */
    readonly command: string;
    /** Extra argv passed to the binary. */
    readonly extraArgs?: readonly string[];
}

/** Result of an `execFile` call, normalized to string stdout/stderr. */
interface ExecResult {
    readonly stdout: string;
    readonly stderr: string;
}

/**
 * Run `command args...` and resolve its captured `{stdout, stderr}`.
 *
 * Wraps node:child_process `execFile` with a `Promise` rather than
 * `util.promisify` so the types resolve without forcing casts — `execFile`'s
 * overloads return `ChildProcess`, which `promisify` cannot infer a useful
 * promise type from. Rejects with an `ExecException`-shaped `Error` on
 * non-zero exit, timeout, or spawn failure.
 */
function runExecFile(
    command: string,
    args: readonly string[],
    options: ExecFileOptionsWithStringEncoding,
): Promise<ExecResult> {
    return new Promise((resolve, reject) => {
        execFile(command, args, options, (err: ExecException | null, stdout, stderr) => {
            if (err !== null) {
                reject(wrapExecError(err));
                return;
            }
            resolve({ stdout, stderr });
        });
    });
}

/**
 * Narrow an `ExecException | null` rejection into a concrete `Error` for
 * `Promise.reject`. The callback parameter's union type does not narrow for
 * some lint rules, so we re-check locally and return a known `Error` here.
 */
function wrapExecError(err: ExecException | null): Error {
    return err instanceof Error ? err : new Error(JSON.stringify(err));
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
            const out = await runExecFile(this.command, args, {
                timeout: 30_000,
                maxBuffer: 64 * 1024 * 1024,
                encoding: "utf8",
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
