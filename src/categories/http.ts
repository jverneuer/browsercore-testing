/**
 * Test Categories 5–7 — HTTP/1.1, HTTP/2, Header Profiles.
 *
 * See docs/TEST-SUITE.md for the full acceptance criteria of each category.
 */

import { describe, it } from "vitest";
import { TestCategory } from "../types.js";

export const CATEGORY_ID_HTTP1 = TestCategory.Http1;
export const CATEGORY_ID_HTTP2 = TestCategory.Http2;
export const CATEGORY_ID_HEADERS = TestCategory.HeaderProfiles;

describe(CATEGORY_ID_HTTP1, () => {
    it.todo("header serialization");
    it.todo("header ordering");
    it.todo("connection reuse");
    it.todo("chunked encoding");
    it.todo("compression");
    it.todo("redirect handling");
    it.todo("cookie handling");
    it.todo("Keep-Alive behavior");
});

describe(CATEGORY_ID_HTTP2, () => {
    it.todo("SETTINGS values match reference");
    it.todo("SETTINGS ordering matches reference");
    it.todo("SETTINGS ACK timing matches reference");
    it.todo("WINDOW_UPDATE values match reference");
    it.todo("frame ordering matches reference");
    it.todo("PING handling matches reference");
    it.todo("GOAWAY handling matches reference");
    it.todo("stream prioritization matches reference (where implemented)");
    it.todo("HPACK behavior matches reference");
    it.todo("pseudo-header ordering matches reference");
});

describe(CATEGORY_ID_HEADERS, () => {
    it.todo("User-Agent header matches profile");
    it.todo("Accept header matches profile");
    it.todo("Accept-Language header matches profile");
    it.todo("Accept-Encoding header matches profile");
    it.todo("Cache-Control header matches profile");
    it.todo("Upgrade-Insecure-Requests header matches profile");
    it.todo("Sec-CH-UA header matches profile");
    it.todo("Sec-CH-UA-Mobile header matches profile");
    it.todo("Sec-CH-UA-Platform header matches profile");
    it.todo("Fetch Metadata headers match profile");
    it.todo("header ordering matches profile");
});
