#!/usr/bin/env python3
"""Detailed analysis of key profiles for divergence report."""
import json, os
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")

def load(p):
    with open(os.path.join(OUT, f"{p}.json")) as f:
        return json.load(f)

KEY = ["chrome131","chrome133a","chrome136","firefox133","firefox135","safari170","safari180","safari184","edge99","chrome124"]

for p in KEY:
    d = load(p)
    tls = d["tls"]; h2 = d["http2"]
    print(f"\n{'='*70}")
    print(f"PROFILE: {p}")
    print(f"{'='*70}")
    print(f"  user_agent: {d.get('user_agent')}")
    print(f"  http_version: {d.get('http_version')}")
    print(f"  tls_version_negotiated: {tls.get('tls_version_negotiated')}")
    print(f"  tls_version_record: {tls.get('tls_version_record')}")
    print(f"  ja3_hash: {tls.get('ja3_hash')}")
    print(f"  ja3: {tls.get('ja3')}")
    print(f"  ja4: {tls.get('ja4')}")
    print(f"  ja4_r: {tls.get('ja4_r')}")
    print(f"  peetprint_hash: {tls.get('peetprint_hash')}")
    print(f"  akamai_fingerprint: {h2.get('akamai_fingerprint')}")
    print(f"  akamai_fingerprint_hash: {h2.get('akamai_fingerprint_hash')}")
    print(f"  client_random: {tls.get('client_random','')[:40]}...")
    print(f"  session_id: {tls.get('session_id','')[:40]}...")
    print(f"\n  --- CIPHERS ({len(tls.get('ciphers',[]))}) ---")
    for c in tls.get("ciphers", []):
        print(f"    {c}")
    print(f"\n  --- EXTENSIONS ({len(tls.get('extensions',[]))}) ---")
    for i, e in enumerate(tls.get("extensions", [])):
        name = e.get("name","?")
        extra = ""
        if "supported_versions" in name:
            extra = " -> " + str(e.get("supported_versions"))
        elif "key_share" in name:
            extra = " -> " + str([list(k.keys())[0] for k in e.get("shared_keys",[])])
        elif "signature_algorithms" in name:
            extra = " -> " + str(e.get("signature_algorithms"))
        elif "application_layer_protocol_negotiation" in name:
            extra = " -> " + str(e.get("protocols"))
        elif "supported_groups" in name:
            extra = " -> " + str(e.get("supported_groups"))
        elif "ec_point_formats" in name or "psk_key_exchange" in name:
            pass
        elif "application_settings" in name:
            extra = " -> " + str(e.get("protocols"))
        elif "compress_certificate" in name:
            extra = " -> " + str(e.get("algorithms"))
        print(f"    [{i:2d}] {name}{extra}")
    print(f"\n  --- HTTP/2 FRAMES ---")
    for fr in h2.get("sent_frames", []):
        ft = fr.get("frame_type")
        if ft == "SETTINGS":
            print(f"    SETTINGS: {fr.get('settings')}")
        elif ft == "WINDOW_UPDATE":
            print(f"    WINDOW_UPDATE: increment={fr.get('increment')}")
        elif ft == "HEADERS":
            print(f"    HEADERS stream={fr.get('stream_id')} flags={fr.get('flags')} priority={fr.get('priority')}")
            for h in fr.get("headers", []):
                print(f"      {h}")
        else:
            print(f"    {ft}: { {k:v for k,v in fr.items() if k != 'frame_type'} }")
