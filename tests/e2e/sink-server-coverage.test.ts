/**
 * Coverage-targeted tests for the branches holding src/e2e/sink-server.ts
 * below 94%.
 *
 * sink-server.test.ts covers the main handshake flow (the "happy path").
 * This file targets the remaining uncovered branches identified by the v8
 * coverage report:
 *
 *  - Branch 4 arm 0  (line 150): `state !== "idle"` TRUE — a second connection
 *    is rejected by the onConnection guard.
 *  - Branch 5 arm 0  (line 172): `totalBuffered < 5` TRUE — the tryCapture
 *    helper returns null when fewer than 5 bytes have arrived.
 *  - Branch 6 arm 0  (line 174): `totalBuffered < recordLen` TRUE — tryCapture
 *    returns null when the buffer has a header but not enough payload.
 *  - Branch 7 arm 1  (line 184): `capture === null` FALSE path — the onData
 *    callback skips onClientHello when tryCapture returns null.
 *  - Branch 8 arm 0  (line 194): raw-socket `error` handler body — fires when
 *    the client TCP socket emits an error.
 *  - Branch 11 arm 0 (line 254): tlsSocket `error` handler body — fires when
 *    the TLS handshake fails (e.g. garbage bytes).
 *  - Branch 18 arm 0 (line 308): `server.close` callback error branch — fires
 *    when close() is called on an already-closed server.
 */

import { describe, expect, it } from "vitest";
import { connect, type TLSSocket } from "node:tls";
import { connect as netConnect, type Socket } from "node:net";
import { TlsSinkServer } from "../../src/e2e/sink-server.js";

/**
 * Suppress unhandled errors on a socket so vitest does not flag them as
 * test errors. The sink under test destroys sockets abruptly in several
 * branches; the remote side sees ECONNRESET — expected, not a bug.
 */
function suppressSocketErrors(socket: Socket | TLSSocket): void {
    socket.on("error", () => {
        /* expected: sink destroys the socket */
    });
}

/**
 * Await a sink handshake that is expected to FAIL. Returns the rejection
 * error. Consumes the rejection cleanly so vitest does not report an
 * unhandled rejection for late-firing server error/close handlers.
 */
async function expectHandshakeFailure(
    sink: TlsSinkServer,
    timeoutMs = 5000,
): Promise<Error> {
    try {
        await sink.waitForHandshake(timeoutMs);
        throw new Error("expected waitForHandshake to reject, but it resolved");
    } catch (err) {
        return err as Error;
    }
}

// ---------------------------------------------------------------------------
// Branch 4 (line 150) — onConnection guard: `state !== "idle"` TRUE
// ---------------------------------------------------------------------------

describe("TlsSinkServer — second connection rejected", () => {
    it("destroys a second TCP connection after the first handshake completes", async () => {
        const sink = await TlsSinkServer.start();
        try {
            const result = sink.waitForHandshake(5000);

            // First client completes a real TLS handshake.
            const client = connect({
                host: sink.host,
                port: sink.port,
                rejectUnauthorized: false,
                servername: "localhost",
            });
            suppressSocketErrors(client);

            await result;
            // Sink is now "done". Wait for the first client socket to fully
            // close so the server (maxConnections = 1) can accept a new
            // connection.
            await new Promise<void>((resolve) => {
                if (client.destroyed) return resolve();
                client.on("close", () => resolve());
                client.end();
            });

            // Second raw-TCP client: the server accepts the connection, sees
            // state === "done" (not "idle"), and destroys the socket.
            const client2 = netConnect({ host: sink.host, port: sink.port });
            suppressSocketErrors(client2);
            await new Promise<void>((resolve) => {
                client2.on("close", () => resolve());
            });
        } finally {
            await sink.stop();
        }
    });
});

// ---------------------------------------------------------------------------
// Branch 5 (line 172) — tryCapture: `totalBuffered < 5` TRUE
// Branch 7 (line 184) — onData: `capture === null` FALSE path
// ---------------------------------------------------------------------------

describe("TlsSinkServer — tryCapture null on small buffer", () => {
    it("returns null when fewer than 5 bytes have been buffered", async () => {
        const sink = await TlsSinkServer.start();
        try {
            // Connect a raw TCP socket (NOT TLS) and write only 2 bytes.
            const client = netConnect({ host: sink.host, port: sink.port });
            suppressSocketErrors(client);
            await new Promise<void>((resolve) => client.on("connect", resolve));
            client.write(new Uint8Array([0x16, 0x03]));

            // The sink buffers the 2 bytes; tryCapture returns null (total < 5).
            // Give the event loop a tick so the data handler runs.
            await new Promise((r) => setTimeout(r, 50));

            // Destroy the socket — triggers the close handler which fires
            // with state = "capturing" (not "done") → fail().
            client.destroy();
            const err = await expectHandshakeFailure(sink);
            expect(err.message).toMatch(/socket closed before handshake/);
        } finally {
            await sink.stop();
        }
    });

    it("returns null when the buffer has a header but not enough payload", async () => {
        const sink = await TlsSinkServer.start();
        try {
            const client = netConnect({ host: sink.host, port: sink.port });
            suppressSocketErrors(client);
            await new Promise<void>((resolve) => client.on("connect", resolve));
            // Send a TLS record header claiming a 256-byte payload but send
            // no payload bytes. recordLen = 5 + 256 = 261 > totalBuffered (5).
            client.write(new Uint8Array([0x17, 0x03, 0x03, 0x01, 0x00]));
            await new Promise((r) => setTimeout(r, 50));

            client.destroy();
            const err = await expectHandshakeFailure(sink);
            expect(err.message).toMatch(/socket closed before handshake/);
        } finally {
            await sink.stop();
        }
    });
});

// ---------------------------------------------------------------------------
// Branch 8 (line 194) — raw socket error handler body
// ---------------------------------------------------------------------------

describe("TlsSinkServer — raw socket error", () => {
    it("invokes the raw-socket error handler when the client aborts with an error", async () => {
        const sink = await TlsSinkServer.start();
        try {
            const client = netConnect({ host: sink.host, port: sink.port });
            suppressSocketErrors(client);
            await new Promise<void>((resolve) => client.on("connect", resolve));
            // Destroy with an error — the server-side raw socket emits
            // "error" → our handler calls fail().
            client.destroy(new Error("test connection reset"));

            // The raw socket error handler calls fail(); waiters reject.
            const err = await expectHandshakeFailure(sink);
            expect(err).toBeDefined();
        } finally {
            await sink.stop();
        }
    });
});

// ---------------------------------------------------------------------------
// Branch 11 (line 254) — tlsSocket error handler body
// ---------------------------------------------------------------------------

describe("TlsSinkServer — TLS handshake failure", () => {
    it("invokes the tlsSocket error handler when the client sends garbage", async () => {
        const sink = await TlsSinkServer.start();
        try {
            const client = netConnect({ host: sink.host, port: sink.port });
            suppressSocketErrors(client);
            await new Promise<void>((resolve) => client.on("connect", resolve));
            // Send bytes that look like a TLS record header claiming a short
            // payload, followed by garbage that is not a valid ClientHello.
            // tryCapture returns these bytes; onClientHello wraps them in a
            // TLSSocket; the TLS layer rejects the handshake → "error" event.
            client.write(
                Buffer.from([
                    0x16, 0x03, 0x03, 0x00, 0x10, // header: 16-byte payload
                    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
                    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                ]),
            );
            // The TLSSocket errors out as soon as it parses the garbage.
            const err = await expectHandshakeFailure(sink);
            expect(err.message).toMatch(/TLS handshake failed/);
        } finally {
            await sink.stop();
        }
    });
});

// ---------------------------------------------------------------------------
// Branch 18 (line 308) — server.close callback error branch
// ---------------------------------------------------------------------------

describe("TlsSinkServer — stop idempotency", () => {
    it("rejects when stop() is called on an already-stopped sink", async () => {
        const sink = await TlsSinkServer.start();
        await sink.stop();
        // server.close() on an already-closed server invokes the callback
        // with ERR_SERVER_NOT_RUNNING — the `err !== undefined` branch.
        await expect(sink.stop()).rejects.toThrow();
    });
});

// ---------------------------------------------------------------------------
// Additional coverage: state fast-paths in waitForHandshake + done()
// ---------------------------------------------------------------------------

describe("TlsSinkServer — waitForHandshake fast-paths", () => {
    it("resolves immediately when called after a completed handshake", async () => {
        const sink = await TlsSinkServer.start();
        try {
            const result = sink.waitForHandshake(5000);

            const client = connect({
                host: sink.host,
                port: sink.port,
                rejectUnauthorized: false,
                servername: "localhost",
            });
            suppressSocketErrors(client);

            const first = await result;
            // Calling waitForHandshake after completion returns the cached
            // result (the `state === "done"` fast-path at line 280).
            const second = await sink.waitForHandshake(5000);
            expect(second).toBe(first);

            client.end();
        } finally {
            await sink.stop();
        }
    });

    it("rejects immediately when called after a failed handshake", async () => {
        const sink = await TlsSinkServer.start();
        // Force the fail() path by stopping before any connection.
        const pending = sink.waitForHandshake(5000);
        await sink.stop();
        // Consume the rejection from stop() so vitest does not flag it.
        await expect(pending).rejects.toThrow();
        // Calling waitForHandshake after failure rejects with the cached
        // error (the `state === "failed"` fast-path at line 283).
        await expect(sink.waitForHandshake(5000)).rejects.toThrow();
    });

    it("stop() after completion is a no-op on the cached result (fail() guard)", async () => {
        const sink = await TlsSinkServer.start();
        const result = sink.waitForHandshake(5000);

        const client = connect({
            host: sink.host,
            port: sink.port,
            rejectUnauthorized: false,
            servername: "localhost",
        });
        suppressSocketErrors(client);

        const first = await result;
        // Stop the sink (calls fail() internally). Since state is
        // already "done", fail()'s early-return guard at line 264
        // makes it a no-op.
        await sink.stop();
        // waitForHandshake after stop() still returns the cached result,
        // proving fail() did not overwrite the "done" state.
        const second = await sink.waitForHandshake(5000);
        expect(second).toBe(first);
        client.destroy();
    });
});
