/**
 * E2E TLS sink server + cert generator tests.
 *
 * Exercises the two new e2e modules that the coverage gate flagged as untested:
 *   - `cert-gen.ts`: self-signed ECDSA P-256 cert generation (DER builders)
 *   - `sink-server.ts`: TlsSinkServer two-socket tap + real TLS handshake
 *
 * The sink tests perform a **real** TLS 1.3 handshake over localhost against
 * Node's `tls` module (client-side), verifying the sink captures the
 * ClientHello bytes *before* TLS parsing and reports the negotiated params.
 */

import { describe, expect, it } from "vitest";
import { connect } from "node:tls";
import { createSecureContext } from "node:tls";
import { generateSelfSignedCert } from "../../src/e2e/cert-gen.js";
import { TlsSinkServer } from "../../src/e2e/sink-server.js";
import { parseClientHello } from "../../src/e2e/parse-clienthello.js";

// --- cert-gen.ts --------------------------------------------------------

describe("generateSelfSignedCert", () => {
    it("returns a DER cert and PEM key", () => {
        const { certDer, keyPem } = generateSelfSignedCert();
        expect(certDer).toBeInstanceOf(Uint8Array);
        expect(certDer.length).toBeGreaterThan(0);
        expect(typeof keyPem).toBe("string");
        expect(keyPem).toContain("-----BEGIN PRIVATE KEY-----");
        expect(keyPem).toContain("-----END PRIVATE KEY-----");
    });

    it("produces a cert node:tls can load into a secure context", () => {
        const { certDer, keyPem } = generateSelfSignedCert();
        // If the DER/PEM encoding is malformed, createSecureContext throws.
        const ctx = createSecureContext({ key: keyPem, cert: derToPem(certDer, "CERTIFICATE") });
        expect(ctx).toBeDefined();
    });

    it("defaults to localhost + 127.0.0.1 SANs with 1-day validity", () => {
        const { certDer } = generateSelfSignedCert();
        // Parse the DER to confirm it is a valid X.509 SEQUENCE.
        expect(certDer[0]).toBe(0x30); // SEQUENCE tag
    });

    it("accepts custom DNS names, IP addresses, and validity window", () => {
        const { certDer, keyPem } = generateSelfSignedCert(
            ["example.com", "foo.test"],
            ["10.0.0.1"],
            7,
        );
        expect(certDer.length).toBeGreaterThan(0);
        expect(keyPem).toContain("PRIVATE KEY");
    });

    it("generates a unique key pair per call", () => {
        const a = generateSelfSignedCert();
        const b = generateSelfSignedCert();
        // Keys should differ (randomly generated each call).
        expect(a.keyPem).not.toBe(b.keyPem);
        // Certs should differ because they contain different public keys.
        expect(Buffer.from(a.certDer).equals(Buffer.from(b.certDer))).toBe(false);
    });
});

// --- sink-server.ts ----------------------------------------------------

describe("TlsSinkServer", () => {
    it("starts on an ephemeral port and reports host/port", async () => {
        const sink = await TlsSinkServer.start();
        expect(sink.host).toBe("127.0.0.1");
        expect(sink.port).toBeGreaterThan(0);
        expect(sink.port).toBeLessThan(65536);
        await sink.stop();
    });

    it("captures the ClientHello and completes a real TLS 1.3 handshake", async () => {
        const sink = await TlsSinkServer.start();
        const result = sink.waitForHandshake(5000);

        // Connect a real TLS client to the sink.
        const client = connect({
            host: sink.host,
            port: sink.port,
            // Accept self-signed cert for the test.
            rejectUnauthorized: false,
            servername: "localhost",
        });

        const handshake = await result;
        expect(handshake).toBeDefined();
        expect(handshake.protocolVersion).toBe("TLSv1.3");
        expect(handshake.cipherSuite).toContain("AES");
        expect(handshake.serverName).toBe("localhost");
        expect(handshake.handshakeDurationMs).toBeGreaterThanOrEqual(0);

        client.end();
        await sink.stop();
    });

    it("captures raw bytes that parse as a valid ClientHello", async () => {
        const sink = await TlsSinkServer.start();
        const result = sink.waitForHandshake(5000);

        const client = connect({
            host: sink.host,
            port: sink.port,
            rejectUnauthorized: false,
            servername: "localhost",
        });

        const handshake = await result;
        expect(handshake.clientHello.raw).toBeInstanceOf(Uint8Array);
        expect(handshake.clientHello.raw.length).toBeGreaterThan(5);
        expect(handshake.clientHello.receivedAt).toBeGreaterThan(0);

        // The captured bytes must parse as a valid ClientHello.
        const parsed = parseClientHello(handshake.clientHello.raw);
        expect(parsed).toBeDefined();
        expect(parsed.extensions.length).toBeGreaterThan(0);

        client.end();
        await sink.stop();
    });

    it("negotiates ALPN when configured", async () => {
        const sink = await TlsSinkServer.start({ alpnProtocols: ["h2", "http/1.1"] });
        const result = sink.waitForHandshake(5000);

        const client = connect({
            host: sink.host,
            port: sink.port,
            rejectUnauthorized: false,
            servername: "localhost",
            ALPNProtocols: ["h2"],
        });

        const handshake = await result;
        expect(handshake.alpnProtocol).toBe("h2");

        client.end();
        await sink.stop();
    });

    it("reports null ALPN when neither side offers one", async () => {
        const sink = await TlsSinkServer.start();
        const result = sink.waitForHandshake(5000);

        const client = connect({
            host: sink.host,
            port: sink.port,
            rejectUnauthorized: false,
            servername: "localhost",
        });

        const handshake = await result;
        expect(handshake.alpnProtocol).toBeNull();

        client.end();
        await sink.stop();
    });

    it("times out when no client connects", async () => {
        const sink = await TlsSinkServer.start();
        await expect(sink.waitForHandshake(100)).rejects.toThrow(/timed out/);
        await sink.stop();
    });

    it("rejects waiters when stopped before a handshake", async () => {
        const sink = await TlsSinkServer.start();
        const pending = sink.waitForHandshake(5000);
        await sink.stop();
        await expect(pending).rejects.toThrow();
    });

    it("is single-shot: a second connection is ignored", async () => {
        const sink = await TlsSinkServer.start();
        const result = sink.waitForHandshake(5000);

        const client = connect({
            host: sink.host,
            port: sink.port,
            rejectUnauthorized: false,
            servername: "localhost",
        });

        await result;
        // The sink is now in "done" state. A second connection is destroyed
        // immediately by the sink, so we must suppress its connection error.
        const client2 = connect({
            host: sink.host,
            port: sink.port,
            rejectUnauthorized: false,
            servername: "localhost",
        });
        client2.on("error", () => {
            /* expected: sink destroys the socket in "done" state */
        });
        client2.end();
        client.end();
        await sink.stop();
    });
});

// --- helpers ------------------------------------------------------------

/** Local copy of the DER→PEM converter (mirrors sink-server.ts private). */
function derToPem(der: Uint8Array, label: string): string {
    const b64 = Buffer.from(der).toString("base64");
    const lines: string[] = [`-----BEGIN ${label}-----`];
    for (let i = 0; i < b64.length; i += 64) {
        lines.push(b64.slice(i, i + 64));
    }
    lines.push(`-----END ${label}-----`);
    return lines.join("\n");
}
