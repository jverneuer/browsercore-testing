/**
 * Node.js-backed implementations of the testing package's provider interfaces.
 *
 * This is the ONLY module in @browsercore/testing that may import `node:fs`
 * and `node:path` directly — the provider boundary that isolates the runtime
 * per Rule 21 (CODING_STANDARDS.md "Runtime independence & dependency
 * injection"). Every other module depends on the
 * {@link FileSystemProvider}/{@link PathProvider} interfaces and never touches
 * the runtime built-ins.
 *
 * Higher layers call the provider methods here, never `node:fs`/`node:path`
 * directly, so the backend stays replaceable. Exported as default singletons
 * so consumers can call `fileSystem.readFileSync(...)` without threading a
 * provider through every constructor.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { FileSystemProvider, PathProvider } from "./provider.js";

/**
 * `node:fs`-backed implementation of {@link FileSystemProvider}.
 *
 * The production testing layers call the default singleton (`fileSystem`) —
 * they never construct this class directly. Tests inject a fake provider
 * through the `FileSystemProvider` interface.
 */
export class NodeFileSystemProvider implements FileSystemProvider {
    public readFileSync(path: string): Uint8Array {
        return readFileSync(path);
    }

    public readFileText(path: string): string {
        return readFileSync(path, "utf8");
    }
}

/**
 * `node:path`-backed implementation of {@link PathProvider}.
 *
 * The production testing layers call the default singleton (`path`) — they
 * never construct this class directly. Tests inject a fake provider through
 * the `PathProvider` interface.
 */
export class NodePathProvider implements PathProvider {
    public join(...parts: string[]): string {
        return join(...parts);
    }
}

/** Default file-system backend higher layers call into. */
export const fileSystem: FileSystemProvider = new NodeFileSystemProvider();

/** Default path backend higher layers call into. */
export const path: PathProvider = new NodePathProvider();
