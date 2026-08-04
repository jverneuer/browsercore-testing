#!/usr/bin/env python3
"""
Probe multiple browser profiles with curl_cffi against tls.peet.ws/api/all.
Saves full JSON per profile + a summary TSV of key fingerprint fields.
"""
import json
import sys
import os
import traceback
from datetime import datetime, timezone
from curl_cffi import requests

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")
os.makedirs(OUT, exist_ok=True)

PROFILES = [
    "chrome99", "chrome100", "chrome101", "chrome104", "chrome107",
    "chrome110", "chrome116", "chrome119", "chrome120", "chrome123",
    "chrome124", "chrome131", "chrome133a", "chrome136",
    "edge99", "edge101",
    "safari155", "safari170", "safari180", "safari184",
    "safari180_ios", "safari260",
    "firefox133", "firefox135",
]

URL = "https://tls.peet.ws/api/all"


def probe(profile):
    resp = requests.get(URL, impersonate=profile, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    # Save raw JSON
    with open(os.path.join(OUT, f"{profile}.json"), "w") as f:
        json.dump(data, f, indent=2)
    return data


def extract(d, profile):
    """Extract summary fields from a tls.peet.ws response."""
    tls = d.get("tls", {})
    h2 = d.get("http2", {})
    # SETTINGS
    settings_map = {}
    settings_order = []
    window_update = None
    headers_list = []
    header_order = []
    priority_info = None
    akamai = h2.get("akamai_fingerprint", "")
    for fr in h2.get("sent_frames", []):
        if fr.get("frame_type") == "SETTINGS":
            for s in fr.get("settings", []):
                k, v = s.split(" = ", 1)
                settings_map[k] = v
                settings_order.append(k)
        elif fr.get("frame_type") == "WINDOW_UPDATE":
            window_update = fr.get("increment")
        elif fr.get("frame_type") == "HEADERS":
            headers_list = fr.get("headers", [])
            header_order = [h.split(":")[0] for h in headers_list]
            if "priority" in fr:
                priority_info = fr["priority"]
    # TLS extension order (names)
    ext_names = [e.get("name", "?") for e in tls.get("extensions", [])]
    # supported_versions + key_share groups order + sig_algs + ciphers
    supported_versions = []
    key_share_groups = []
    sig_algs = []
    ec_point_formats = []
    ciphers = tls.get("ciphers", [])
    for e in tls.get("extensions", []):
        nm = e.get("name", "")
        if "supported_versions" in nm:
            supported_versions = e.get("supported_versions", [])
        elif "key_share" in nm:
            for k in e.get("shared_keys", []):
                key_share_groups += list(k.keys())
        elif "signature_algorithms" in nm:
            sig_algs = e.get("signature_algorithms", [])
        elif "ec_point_formats" in nm or "psk_key_exchange" in nm:
            pass
        if "ec_point_formats" in nm:
            ec_point_formats = e.get("elliptic_curves", [])
    # request headers ordering (non-pseudo)
    request_headers = [h.split(":")[0] for h in headers_list]
    pseudo_order = [h for h in request_headers if h.startswith(":")]
    regular_order = [h for h in request_headers if not h.startswith(":")]
    return {
        "profile": profile,
        "http_version": d.get("http_version"),
        "user_agent": d.get("user_agent"),
        "ja3_hash": tls.get("ja3_hash"),
        "ja3": tls.get("ja3"),
        "ja4": tls.get("ja4"),
        "ja4_r": tls.get("ja4_r"),
        "tls_version_negotiated": tls.get("tls_version_negotiated"),
        "tls_version_record": tls.get("tls_version_record"),
        "ciphers": ciphers,
        "settings_order": settings_order,
        "settings_map": settings_map,
        "window_update": window_update,
        "akamai_fingerprint": akamai,
        "pseudo_header_order": pseudo_order,
        "regular_header_order": regular_order,
        "priority_info": priority_info,
        "extension_names": ext_names,
        "supported_versions": supported_versions,
        "key_share_groups": key_share_groups,
        "sig_algs": sig_algs,
        "ec_point_formats": ec_point_formats,
        "num_extensions": len(ext_names),
    }


def main():
    results = []
    failures = []
    for p in PROFILES:
        try:
            d = probe(p)
            s = extract(d, p)
            results.append(s)
            print(f"OK   {p:16s} ja3={s['ja3_hash']} ja4={s['ja4']} settings={s['settings_order']}")
        except Exception as e:
            failures.append((p, str(e)))
            print(f"FAIL {p:16s} -> {e}")
    # Save summary
    with open(os.path.join(OUT, "summary.json"), "w") as f:
        json.dump({"probed_at": datetime.now(timezone.utc).isoformat(),
                   "results": results, "failures": failures}, f, indent=2)
    print(f"\n=== {len(results)} OK, {len(failures)} FAILED ===")
    print("Failures:", failures)


if __name__ == "__main__":
    main()
