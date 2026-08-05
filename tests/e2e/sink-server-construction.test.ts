/**
 * Coverage-targeted tests for the sink-server.ts *construction* branches
 * that a real net.Server on an ephemeral port can never exercise.
 *
 * sink-server.test.ts and sink-server-coverage.test.ts drive the sink once it
 * is listening (handshake flow, second-connection guard, socket/TLS errors).
 * This file targets the two remaining branches inside TlsSinkServer.start()'s
 * Promise executor:
 *
 *  - Line 123: the server `"error"` handler body — `reject(err)` when the
 *    underlying net.Server emits an error before the sink finishes
 *    constructing.
 *  - Lines 129-130: the `addr === null || typeof addr === "string"` guard —
 *    `reject(...)` + `return` when server.address() does not return an
 *    AddressInfo object (never happens with a real TCP listen on port 0, so
 *    it is unreachable without mocking).
 *
 * We mock node:net's createServer to return a fake server whose `listen` and
 * `address` behavior the test controls. The fake captures the error + listen
 * callbacks so the test can fire them on demand.
 */

import { vi, describe, expect, it, beforeEach } from "vitest";

/**
 * Controller the tests use to drive the fake server. Populated by the mock
 * server as the real start() registers handlers; the tests fire them.
 */
interface ConstructionController {
    /** Invoke the error handler registered via server.on("error", ...). */
    fireError: (err: Error) => void;
    /** Invoke the callback registered via server.listen(..., cb). */
    fireListen: () => void;
    /** Value server.address() returns. */
    addressValue: AddressLike;
}

type AddressLike = { address: string; port: number; family: string } | null | string;

const { controller } = vi.hoisted(() => {
    const ctrl: ConstructionController = {
        fireError: () => {
            /* replaced by the mock's on("error") */
        },
        fireListen: () => {
            /* replaced by the mock's listen(...) */
        },
        addressValue: null,
    };
    return { controller: ctrl };
});

/** Build a fake net.Server that routes its callbacks through the controller. */
function makeMockServer(): ReturnType<typeof netCreateServerStub> {
    const server: Record<string, unknown> = {
        maxConnections: Infinity,
        on(event: string, cb: (...args: unknown[]) => void) {
            if (event === "error") {
                controller.fireError = cb as (err: Error) => void;
            }
            return server;
        },
        listen(_port: number, _host: string, cb: () => void) {
            controller.fireListen = cb;
            return server;
        },
        address() {
            return controller.addressValue;
        },
        close(cb?: (err?: Error) => void) {
            if (cb) cb();
        },
    };
    return server as ReturnType<typeof netCreateServerStub>;
}

// Minimal stand-in signature for node:net's createServer; only the shape
// start() touches (on, listen, address, maxConnections) matters at runtime.
function netCreateServerStub(): never {
    throw new Error("mock placeholder — replaced by vi.mock");
}

vi.mock("node:net", async (importOriginal) => {
    const actual = await importOriginal<typeof import("node:net")>();
    return {
        ...actual,
        createServer: vi.fn(() => makeMockServer()),
    };
});

import { TlsSinkServer } from "../../src/e2e/sink-server.js";

beforeEach(() => {
    controller.fireError = () => {};
    controller.fireListen = () => {};
    controller.addressValue = null;
});

describe("TlsSinkServer.start — construction error handler (line 123)", () => {
    it("rejects when the server emits an error before construction completes", async () => {
        // start() registers the error handler before calling listen, so by the
        // time it returns the promise the handler is captured. Firing an
        // error triggers the `reject(err)` at sink-server.ts line 123.
        const startPromise = TlsSinkServer.start();
        const boom = new Error("mock listen failure");
        controller.fireError(boom);
        await expect(startPromise).rejects.toThrow(/mock listen failure/);
    });
});

describe("TlsSinkServer.start — address guard (lines 129-130)", () => {
    it("rejects when server.address() returns null", async () => {
        // start() calls listen; the listen callback reads server.address().
        // When it is null, the `addr === null || typeof addr === "string"`
        // guard fires and start() rejects — the branch at lines 129-130.
        controller.addressValue = null;
        const startPromise = TlsSinkServer.start();
        controller.fireListen();
        await expect(startPromise).rejects.toThrow(/did not bind to an ephemeral port/);
    });

    it("rejects when server.address() returns a string (pipe/unix socket)", async () => {
        // typeof addr === "string" is the other half of the same guard —
        // a non-TCP transport. Verifies both arms of the `||` reject.
        controller.addressValue = "/tmp/sink.sock";
        const startPromise = TlsSinkServer.start();
        controller.fireListen();
        await expect(startPromise).rejects.toThrow(/did not bind to an ephemeral port/);
    });
});
