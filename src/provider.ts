/**
 * Provider interfaces for the @browsercore/testing package.
 *
 * Protocol/test infrastructure layers isolate runtime-specific dependencies
 * (node:fs, node:path) behind these interfaces per Rule 21
 * (CODING_STANDARDS.md "Runtime independence & dependency injection").
 * Higher layers depend on the interfaces — never on a concrete provider — so
 * the backend is replaceable (in-memory fake for tests, Deno/Bun, ...).
 *
 * @see {@link NodeFileSystemProvider} for the default `node:fs` backend.
 * @see {@link NodePathProvider} for the default `node:path` backend.
 */

/**
 * File-system read operations.
 *
 * Higher layers depend on this interface, never on `node:fs` directly, so the
 * backend is replaceable. All methods take and return `Uint8Array` or
 * `string` — never Node `Buffer` — so the interface is portable across
 * runtimes.
 */
export interface FileSystemProvider {
    /**
     * Read a file's raw bytes.
     *
     * @param path Absolute or relative file path.
     * @returns The file's contents as raw bytes.
     */
    readFileSync(path: string): Uint8Array;

    /**
     * Read a file's text content (utf8).
     *
     * @param path Absolute or relative file path.
     * @returns The file's contents as a utf8 string.
     */
    readFileText(path: string): string;
}

/**
 * Path manipulation operations.
 *
 * Higher layers depend on this interface, never on `node:path` directly, so
 * path resolution is replaceable and testable against synthetic layouts.
 */
export interface PathProvider {
    /**
     * Join path segments into a single path.
     *
     * @param parts Path segments to join.
     * @returns The joined path.
     */
    join(...parts: string[]): string;
}
