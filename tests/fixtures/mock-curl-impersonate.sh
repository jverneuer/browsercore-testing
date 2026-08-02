#!/bin/sh
# Mock curl-impersonate binary for deterministic, offline tests.
# Ignores all arguments and emits a known hex dump in the format
# parseDumpOutput() expects (">>> traffic <<<" marker + hex bytes).
printf '>>> traffic <<<\n'
# 32 bytes of synthetic "TLS record" hex — deterministic, never random.
printf '16030100200100001c0303aaaabbbbccccddddeeeeffff00112233445566778899aabbccddeeff001301000100\n'
