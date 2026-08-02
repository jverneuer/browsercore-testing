#!/bin/sh
# Mock curl-impersonate binary for deterministic, offline tests.
# Ignores all arguments and emits a known hex dump in the format
# parseDumpOutput() expects (">>> traffic <<<" marker + hex bytes).
printf '>>> traffic <<<\n'
# Valid 96-byte record-wrapped TLS 1.3 ClientHello (SNI/groups/EC/ALPN) — the
# same deterministic bytes as captures/chrome-140/tls/client_hello.bin.
printf '160301005b010000570304000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000004130113020100002a00000006000400000161000a00040002001d000b000201000010000f000d02683209687474702f312e31\n'
