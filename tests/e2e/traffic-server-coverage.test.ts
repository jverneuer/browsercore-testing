/**
 * Coverage tests for TrafficServer error/edge-case branches.
 *
 * The happy-path coverage comes from traffic-gate.test.ts, which drives a
 * real TLS handshake. These tests exercise the error paths: second-connection
 * rejection, socket errors, premature close, timeout, and post-fail state.
 */

import { describe, it, expect, afterEach } from "vitest";
import { connect as netConnect, type Socket } from "node:net";
import { TrafficServer } from "../../src/e2e/traffic-server.js";

const servers: TrafficServer[] = [];
afterEach(async () => {
    for (const s of servers) {
        await s.stop().catch(() => {});
    }
    servers.length = 0;
});

describe("TrafficServer — error/edge branches", () => {
    it("rejects a second connection (maxConnections=1, destroys socket)", async () => {
        const server = await TrafficServer.start();
        servers.push(server);

        // First connection (stays open, occupying the single slot)
        const sock1 = netConnect({ host: server.host, port: server.port });
        await new Promise<void>((resolve) => { sock1.on("connect", () => resolve()); });

        // Second connection — should be destroyed immediately
        const sock2 = netConnect({ host: server.host, port: server.port });
        const closed = new Promise<void>((resolve) => { sock2.on("close", () => resolve()); });
        await closed;

        sock1.destroy();
    });

    it("fails when socket closes before handshake completes", async () => {
        const server = await TrafficServer.start();
        servers.push(server);

        const handshakePromise = server.waitForHandshake(5000);

        // Connect and immediately close — no TLS bytes sent
        const sock = netConnect({ host: server.host, port: server.port });
        await new Promise<void>((resolve) => { sock.on("connect", () => resolve()); });
        sock.destroy();

        // The server should fail with "socket closed before handshake"
        await expect(handshakePromise).rejects.toThrow();
    });

    it("waitForHandshake times out after the specified duration", async () => {
        const server = await TrafficServer.start();
        servers.push(server);

        // Connect a raw TCP socket — send no TLS data, so the handshake hangs
        const sock = netConnect({ host: server.host, port: server.port });
        await new Promise<void>((resolve) => { sock.on("connect", () => resolve()); });

        // Short timeout — should reject
        await expect(server.waitForHandshake(200)).rejects.toThrow(/timed out/u);

        sock.destroy();
    });

    it("waitForHandshake returns immediately when state is failed", async () => {
        const server = await TrafficServer.start();
        servers.push(server);

        // Trigger a failure by connecting and closing immediately
        const sock = netConnect({ host: server.host, port: server.port });
        await new Promise<void>((resolve) => { sock.on("connect", () => resolve()); });
        sock.destroy();

        // Wait for the server to register the failure
        await expect(server.waitForHandshake(5000)).rejects.toThrow();

        // Second call should reject immediately (state is "failed")
        await expect(server.waitForHandshake(5000)).rejects.toThrow();
    });

    it("stop() triggers a failure for pending waiters", async () => {
        const server = await TrafficServer.start();
        servers.push(server);

        // Start waiting for a handshake that will never come
        const handshakePromise = server.waitForHandshake(10000);

        // Stop the server — should reject all waiters
        await server.stop();
        await expect(handshakePromise).rejects.toThrow();
    });
});
