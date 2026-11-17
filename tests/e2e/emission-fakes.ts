/**
 * Shared fakes for the REAL emission tests (tests/e2e/emission-*.test.ts).
 *
 * The emission tests drive the REAL protocol stacks (@browsercore/tls,
 * @browsercore/http2) over these injected doubles — pure dependency
 * injection per the code standards: the protocol layers never know the
 * difference between these and a socket.
 */

import type { Transport, TransportId, TransportState } from "@browsercore/transport";
import type { EventProvider } from "@browsercore/contracts";

/**
 * In-memory duplex transport. Captures every client write verbatim; `read()`
 * serves queued server chunks and otherwise parks until data arrives or the
 * transport closes. Writes after close resolve silently so a peer's best-effort
 * farewell write (e.g. a TLS alert) never masks the bytes under test.
 *
 * The canonical `Transport` extends `EventProvider`, so the full 8-method
 * event surface is implemented by composition over the same in-memory
 * provider {@link captureEventProvider} builds — one listener store, no
 * third-party emitter dependency.
 */
export class CaptureTransport implements Transport {
    readonly id: TransportId = "capture-1" as TransportId;
    state: TransportState = { state: "open" };

    /** Every client write, in call order. */
    readonly writes: Uint8Array[] = [];
    private readonly serverQueue: Uint8Array[] = [];
    private pendingRead: ((chunk: Uint8Array) => void) | null = null;
    private pendingReject: ((error: Error) => void) | null = null;
    private readonly events: EventProvider = captureEventProvider();

    write(data: Uint8Array): Promise<void> {
        if (this.state.state === "closed") {
            return Promise.resolve();
        }
        this.writes.push(new Uint8Array(data));
        return Promise.resolve();
    }

    read(): Promise<Uint8Array> {
        const chunk = this.serverQueue.shift();
        if (chunk !== undefined) {
            return Promise.resolve(chunk);
        }
        return new Promise<Uint8Array>((resolve, reject) => {
            this.pendingRead = resolve;
            this.pendingReject = reject;
        });
    }

    async close(): Promise<void> {
        if (this.state.state === "closed") {
            return;
        }
        this.state = { state: "closed", reason: { kind: "client_close" } };
        this.pendingReject?.(new Error("transport closed by peer"));
        this.pendingRead = null;
        this.pendingReject = null;
    }

    /** Feed server → client bytes into the read path. */
    feed(chunk: Uint8Array): void {
        if (this.pendingRead !== null) {
            const resolve = this.pendingRead;
            this.pendingRead = null;
            this.pendingReject = null;
            resolve(chunk);
        } else {
            this.serverQueue.push(chunk);
        }
    }

    // --- EventProvider surface (delegated to the internal store) -----------

    on(event: string, listener: (...args: unknown[]) => void): void {
        this.events.on(event, listener);
    }

    once(event: string, listener: (...args: unknown[]) => void): void {
        this.events.once(event, listener);
    }

    off(event: string, listener: (...args: unknown[]) => void): void {
        this.events.off(event, listener);
    }

    removeListener(event: string, listener: (...args: unknown[]) => void): void {
        this.events.removeListener(event, listener);
    }

    emit(event: string, ...args: unknown[]): boolean {
        return this.events.emit(event, ...args);
    }

    listenerCount(event: string): number {
        return this.events.listenerCount(event);
    }

    removeAllListeners(event?: string): void {
        this.events.removeAllListeners(event);
    }
}

/** Minimal in-memory EventProvider (contract from @browsercore/contracts). */
export function captureEventProvider(): EventProvider {
    const listeners = new Map<string, Set<(...args: unknown[]) => void>>();
    return {
        on: (event, listener) => {
            const set = listeners.get(event) ?? new Set();
            set.add(listener);
            listeners.set(event, set);
        },
        once: (event, listener) => {
            const wrapped = (...args: unknown[]): void => {
                listener(...args);
                listeners.get(event)?.delete(wrapped);
            };
            const set = listeners.get(event) ?? new Set();
            set.add(wrapped);
            listeners.set(event, set);
        },
        off: (event, listener) => {
            listeners.get(event)?.delete(listener);
        },
        removeListener: (event, listener) => {
            listeners.get(event)?.delete(listener);
        },
        emit: (event, ...args) => {
            let had = false;
            for (const listener of listeners.get(event) ?? []) {
                listener(...args);
                had = true;
            }
            return had;
        },
        listenerCount: (event) => listeners.get(event)?.size ?? 0,
        removeAllListeners: (event) => {
            if (event === undefined) {
                listeners.clear();
                return;
            }
            listeners.delete(event);
        },
    };
}

/** Lowercase hex of a byte array — prototype-agnostic for cross-source compares. */
export function toHex(bytes: Uint8Array): string {
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
