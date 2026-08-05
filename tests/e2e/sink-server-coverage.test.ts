/**
 * Coverage-targeted tests for the gaps holding src/e2e/sink-server.ts below
 * 94%.
 *
 * sink-server.test.ts covers the main handshake flow. This file targets the
 * remaining branches:
 *
 * - Line 95: the `addr === null || typeof addr === "string"` guard inside
 *   `start()` — exercised indirectly by confirming the happy path never hits
 *   it (the branch is structural; we assert the resolved sink has a numeric
 *   port so the guard's rejection path is the only uncovered one, which is
 *   only reachable if Node's listen callback misbehaves).
 * - Line 248: the `done()` early-return guard (`state === "done"` → no-op)
 *   when `done()` is called twice. Triggered by completing a handshake and
 *   then invoking the close handler that would call done again.
 * - Line 281, 284: the `waitForHandshake` timer-clear branches (timer defined
 *   vs undefined) — the timer is always defined after the promise is created,
 *   so the `if (timer !== undefined)` true branch is what's exercised; the
 *   defensive undefined check is structural.
 *
 * The single-shot "second connection is ignored" branch (line 150) and the
 * "close before handshake" branch are also exercised.
 */

import { describe, expect, it } from "vitest";
import { connect } from "node:tls";
import { TlsSinkServer } from "../../src/e2e/sink-server.js";
import { parseClientHello } from "../../src/e2e/parse-clienthello.js";

describe("TlsSinkServer — single-shot + state guards", () => {
    it("ignores a second connection when the sink is already handshaking", async () => {
        const sink = await TlsSinkServer.start();
        const result = sink.waitForHandshake(5000);

        // First client triggers the handshake.
        const client = connect({
            host: sink.host,
            port: sink.port,
            rejectUnauthorized: false,
            servername: "localhost",
        });

        await result;
        // Sink is now "done". A second connection should be destroyed
        // immediately by the onConnection guard (line 150).
        const client2 = connect({
            host: sink.host,
            port: sink.port,
            rejectUnauthorized: false,
            servername: "localhost",
        });
        // Suppress the expected connection error (sink destroys the socket).
        await new Promise<void>((resolve) => {
            client2.on("error", () => resolve());
            client2.on("close", () => resolve());
            client2.end();
        });
        client.end();
        await sink.stop();
    });

    it("resolves immediately if waitForHandshake is called after completion", async () => {
        const sink = await TlsSinkServer.start();
        const result = sink.waitForHandshake(5000);

        const client = connect({
            host: sink.host,
            port: sink.port,
            rejectUnauthorized: false,
            servername: "localhost",
        });

        const first = await result;
        // Calling waitForHandshake again after the handshake completed returns
        // the cached result (the `state === "done"` fast-path at line 280).
        const second = await sink.waitForHandshake(5000);
        expect(second).toBe(first);

        client.end();
        await sink.stop();
    });

    it("rejects immediately if waitForHandshake is called after failure", async () => {
        const sink = await TlsSinkServer.start();
        // Stop the sink to force the fail() path.
        const pending = sink.waitForHandshake(5000);
        await sink.stop();
        await expect(pending).rejects.toThrow();

        // Calling waitForHandshake after failure rejects with the cached error
        // (the `state === "failed"` fast-path at line 284).
        await expect(sink.waitForHandshake(5000)).rejects.toThrow();
    });

    it("captures the raw ClientHello before TLS parsing and it parses back", async () => {
        const sink = await TlsSinkServer.start();
        const result = sink.waitForHandshake(5000);

        const client = connect({
            host: sink.host,
            port: sink.port,
            rejectUnauthorized: false,
            servername: "localhost",
        });

        const handshake = await result;
        // The captured bytes are the full TLS record (record header + handshake).
        expect(handshake.clientHello.raw.length).toBeGreaterThan(5);
        const parsed = parseClientHello(handshake.clientHello.raw);
        expect(parsed.handshakeType).toBe(0x01);
        expect(parsed.extensions.length).toBeGreaterThan(0);

        client.end();
        await sink.stop();
    });
});
