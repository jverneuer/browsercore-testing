/**
 * Test Category 8 — Cookie Behavior.
 *
 * Verify RFC 6265 cookie parsing and policy against the @browsercore/cookies
 * implementation. See docs/TEST-SUITE.md ("Test Category 8 — Cookie Behavior")
 * for the full acceptance criteria.
 */

import { describe, expect, it } from "vitest";
import {
    createCookieJar,
    parseSetCookieHeader,
    cookieMatchesUrl,
    isExpired,
    normalizeDomain,
    defaultPath,
    sameSiteAllows,
    CookieParseError,
    type Cookie,
    type CookieUrl,
    type SameSiteContext,
} from "@browsercore/cookies";
import { TestCategory } from "../types.js";

export const CATEGORY_ID = TestCategory.CookieBehavior;

/** Build a {@link CookieUrl} for testing. */
function url(hostname: string, pathname: string, secure = false): CookieUrl {
    return {
        hostname,
        pathname,
        // The @browsercore/cookies Secure check compares protocol against
        // "https:" (with trailing colon), matching the URL standard form.
        protocol: secure ? "https:" : "http:",
    };
}

/** Build a {@link SameSiteContext} for testing. */
function ctx(topLevelSite: string, isTopLevel = false): SameSiteContext {
    return { topLevelSite, isTopLevelNavigation: isTopLevel, method: "GET" };
}

describe(CATEGORY_ID, () => {
    it("parses a Set-Cookie header into a Cookie object", () => {
        const cookie = parseSetCookieHeader("session=abc123; Path=/; Secure; HttpOnly", url("example.com", "/"));
        expect(cookie).not.toBeNull();
        expect(cookie?.name).toBe("session");
        expect(cookie?.value).toBe("abc123");
        expect(cookie?.path).toBe("/");
        expect(cookie?.secure).toBe(true);
        expect(cookie?.httpOnly).toBe(true);
    });

    it("parses a Set-Cookie header with an explicit Domain", () => {
        const cookie = parseSetCookieHeader("id=42; Domain=example.com", url("example.com", "/"));
        expect(cookie).not.toBeNull();
        expect(cookie?.domain).toBe("example.com");
    });

    it("parses a Set-Cookie header with Max-Age", () => {
        const cookie = parseSetCookieHeader("prefs=dark; Max-Age=3600", url("example.com", "/"));
        expect(cookie).not.toBeNull();
        expect(cookie?.maxAge).toBe(3600);
    });

    it("parses a Set-Cookie header with SameSite", () => {
        const lax = parseSetCookieHeader("a=1; SameSite=Lax", url("example.com", "/"));
        expect(lax?.sameSite).toBe("Lax");
        const strict = parseSetCookieHeader("a=1; SameSite=Strict", url("example.com", "/"));
        expect(strict?.sameSite).toBe("Strict");
        const none = parseSetCookieHeader("a=1; SameSite=None; Secure", url("example.com", "/"));
        expect(none?.sameSite).toBe("None");
    });

    it("parses a Set-Cookie header with an explicit Expires", () => {
        const cookie = parseSetCookieHeader(
            "prefs=dark; Expires=Wed, 09 Jun 2021 10:18:14 GMT",
            url("example.com", "/"),
        );
        expect(cookie).not.toBeNull();
        expect(cookie?.expires).toBeInstanceOf(Date);
    });

    it("throws CookieParseError for an empty Set-Cookie header", () => {
        expect(() => parseSetCookieHeader("", url("example.com", "/"))).toThrow(CookieParseError);
    });

    it("parses 'Path=/; Secure' as a cookie named 'Path' with value '/'", () => {
        // The parser is permissive: "Path=/; Secure" is treated as a cookie
        // with name "Path" and value "/", plus the Secure attribute. This is
        // technically a malformed Set-Cookie header, but the parser does not
        // reject it — higher layers should validate before storing.
        const cookie = parseSetCookieHeader("Path=/; Secure", url("example.com", "/"));
        expect(cookie).not.toBeNull();
        expect(cookie?.name).toBe("Path");
        expect(cookie?.value).toBe("/");
        expect(cookie?.secure).toBe(true);
    });

    it("rejects a cookie for a domain mismatch", () => {
        // A cookie set for example.com must NOT match evil.com.
        const cookie = parseSetCookieHeader("session=abc; Domain=example.com", url("example.com", "/"));
        expect(cookie).not.toBeNull();
        if (cookie === null) {
            expect.unreachable("cookie parsed as non-null");
        }
        const evilUrl = url("evil.com", "/");
        const result = cookieMatchesUrl(cookie as Cookie, evilUrl);
        expect(result.matched).toBe(false);
        expect(result.reason).toBe("domain_mismatch");
    });

    it("matches a cookie to its own domain and subdomains", () => {
        const cookie = parseSetCookieHeader("session=abc; Domain=example.com", url("example.com", "/"));
        expect(cookie).not.toBeNull();
        if (cookie === null) {
            expect.unreachable("cookie parsed as non-null");
        }
        const c = cookie as Cookie;
        expect(cookieMatchesUrl(c, url("example.com", "/")).matched).toBe(true);
        expect(cookieMatchesUrl(c, url("www.example.com", "/")).matched).toBe(true);
        expect(cookieMatchesUrl(c, url("deep.sub.example.com", "/")).matched).toBe(true);
    });

    it("respects the Secure flag — no match over http", () => {
        const cookie = parseSetCookieHeader("session=abc; Domain=example.com; Secure", url("example.com", "/"));
        expect(cookie).not.toBeNull();
        if (cookie === null) {
            expect.unreachable("cookie parsed as non-null");
        }
        const c = cookie as Cookie;
        expect(cookieMatchesUrl(c, url("example.com", "/", false)).matched).toBe(false);
        expect(cookieMatchesUrl(c, url("example.com", "/", true)).matched).toBe(true);
    });

    it("respects the Path attribute", () => {
        const cookie = parseSetCookieHeader("session=abc; Domain=example.com; Path=/api", url("example.com", "/api"));
        expect(cookie).not.toBeNull();
        if (cookie === null) {
            expect.unreachable("cookie parsed as non-null");
        }
        const c = cookie as Cookie;
        expect(cookieMatchesUrl(c, url("example.com", "/api")).matched).toBe(true);
        expect(cookieMatchesUrl(c, url("example.com", "/api/v1")).matched).toBe(true);
        expect(cookieMatchesUrl(c, url("example.com", "/other")).matched).toBe(false);
    });

    it("detects an expired cookie by Max-Age", () => {
        const cookie: Cookie = {
            name: "sess",
            value: "x",
            domain: "example.com",
            path: "/",
            expires: undefined,
            maxAge: -1, // expired
            secure: false,
            httpOnly: false,
            sameSite: "Lax",
            partitioned: false,
            hostOnly: false,
            creationTime: Date.now() - 10_000,
            lastAccessTime: Date.now() - 10_000,
        };
        expect(isExpired(cookie, Date.now())).toBe(true);
    });

    it("detects a fresh cookie as not expired", () => {
        const cookie: Cookie = {
            name: "sess",
            value: "x",
            domain: "example.com",
            path: "/",
            expires: undefined,
            maxAge: 3600,
            secure: false,
            httpOnly: false,
            sameSite: "Lax",
            partitioned: false,
            hostOnly: false,
            creationTime: Date.now(),
            lastAccessTime: Date.now(),
        };
        expect(isExpired(cookie, Date.now())).toBe(false);
    });

    it("normalizes a domain to lowercase and strips leading dot", () => {
        expect(normalizeDomain("Example.COM")).toBe("example.com");
        expect(normalizeDomain(".example.com")).toBe("example.com");
    });

    it("computes the default path from a request path", () => {
        expect(defaultPath("/")).toBe("/");
        expect(defaultPath("/foo/bar")).toBe("/foo");
        expect(defaultPath("/foo/bar/baz")).toBe("/foo/bar");
    });

    it("SameSite=Strict blocks cross-site requests", () => {
        const cookie: Cookie = {
            name: "sess",
            value: "x",
            domain: "example.com",
            path: "/",
            expires: undefined,
            maxAge: undefined,
            secure: false,
            httpOnly: false,
            sameSite: "Strict",
            partitioned: false,
            hostOnly: false,
            creationTime: Date.now(),
            lastAccessTime: Date.now(),
        };
        // Same-site → allowed.
        expect(sameSiteAllows(cookie, url("example.com", "/"), ctx("example.com"))).toBe(true);
        // Cross-site → blocked.
        expect(sameSiteAllows(cookie, url("example.com", "/"), ctx("evil.com"))).toBe(false);
    });

    it("SameSite=Lax allows top-level navigations cross-site", () => {
        const cookie: Cookie = {
            name: "sess",
            value: "x",
            domain: "example.com",
            path: "/",
            expires: undefined,
            maxAge: undefined,
            secure: false,
            httpOnly: false,
            sameSite: "Lax",
            partitioned: false,
            hostOnly: false,
            creationTime: Date.now(),
            lastAccessTime: Date.now(),
        };
        // Same-site → allowed.
        expect(sameSiteAllows(cookie, url("example.com", "/"), ctx("example.com"))).toBe(true);
        // Cross-site top-level navigation → allowed.
        expect(sameSiteAllows(cookie, url("example.com", "/"), ctx("evil.com", true))).toBe(true);
    });

    it("createCookieJar stores and retrieves cookies", () => {
        const jar = createCookieJar();
        jar.setCookie("session=abc123; Path=/", url("example.com", "/"));
        const target = url("example.com", "/");
        const cookies = jar.getCookies(target);
        expect(cookies.length).toBe(1);
        expect(cookies[0]?.name).toBe("session");
        expect(cookies[0]?.value).toBe("abc123");
    });

    it("cookie jar does not return cookies for unmatched domains", () => {
        const jar = createCookieJar();
        jar.setCookie("session=abc; Domain=example.com", url("example.com", "/"));
        const cookies = jar.getCookies(url("other.com", "/"));
        expect(cookies).toHaveLength(0);
    });

    it("cookie jar clears all cookies", () => {
        const jar = createCookieJar();
        jar.setCookie("a=1; Path=/", url("example.com", "/"));
        jar.setCookie("b=2; Path=/", url("example.com", "/"));
        jar.clear();
        expect(jar.getCookies(url("example.com", "/"))).toHaveLength(0);
    });

    it("cookie jar serializes and deserializes", () => {
        const jar = createCookieJar();
        jar.setCookie("session=abc123; Path=/", url("example.com", "/"));
        const json = jar.serialize();
        const jar2 = createCookieJar();
        jar2.deserialize(json);
        const cookies = jar2.getCookies(url("example.com", "/"));
        expect(cookies.length).toBe(1);
        expect(cookies[0]?.name).toBe("session");
    });
});
