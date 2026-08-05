/**
 * Coverage-targeted tests for the remaining uncovered branches holding the
 * package below 94% branch coverage.
 *
 * The v8 coverage report flags 49 branches in src/rfc/rfcTests.ts, of which
 * 40 were covered by rfc.test.ts + rfc-coverage.test.ts. One genuine conditional
 * branch remained uncovered: the empty-string early-return in the internal
 * parts() helper (rfcTests.ts L26). The other 8 "uncovered" slots are v8
 * function-entry artifacts ([entered, not_entered] where not_entered is always
 * 0 because the function is called) — these are unreachable without removing
 * the function and are NOT coverable by tests.
 *
 * This file covers the parts() empty-string branch by registering a custom
 * profile backed by a ClientHello capture that has ZERO extensions. When
 * parseClientHello parses that capture it returns extensions: "" and
 * supportedGroups: ""; parts("") then takes the `s.length === 0` true branch
 * (returning [] instead of splitting).
 */

import { describe, expect, it, beforeAll } from "vitest";
import { runTlsCompliance } from "../src/rfc/rfcTests.js";
import { registerProfile } from "@browsercore/profiles";
import type { ProfileId, BrowserProfile } from "../src/types.js";

const stubTls: BrowserProfile["tls"] = {
    cipherSuites: [],
    extensionOrder: [],
    supportedVersions: [],
    keyShareGroups: [],
    signatureAlgorithms: [],
    grease: false,
};
const stubHttp2: BrowserProfile["http2"] = {
    settings: {},
    initialWindowSize: 65535,
    maxFrameSize: 16384,
    maxHeaderListSize: 262144,
};

beforeAll(() => {
    // Register a profile pointing at the no-extensions capture so that
    // parseTlsCapture processes a ClientHello with empty extensions.
    registerProfile({
        tls: stubTls,
        http2: stubHttp2,
        id: "test-no-extensions" as ProfileId,
        name: "test",
        version: "1.0.0",
        http1: {
            defaultHeaders: { host: "example.com" },
            headerOrder: ["host"],
            connection: "keep-alive",
            acceptEncoding: "gzip",
        },
    });
});

describe("runTlsCompliance — no-extensions capture (rfcTests.ts L26)", () => {
    it("covers parts() empty-string branch via a capture with no extensions", () => {
        // The test-no-extensions capture has zero extensions, so
        // parseClientHello returns extensions: "" and supportedGroups: "".
        // parts("") hits the `s.length === 0` true branch (returns []).
        const result = runTlsCompliance("tls_noext" as never, "test-no-extensions" as ProfileId);
        expect(result.pass).toBe(false);
        expect(result.actual).toMatchObject({ extensionTypes: [] });
    });
});
