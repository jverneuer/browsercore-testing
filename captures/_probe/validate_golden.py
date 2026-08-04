#!/usr/bin/env python3
"""Validate reconstructed SETTINGS frames + meta.json schema compliance."""
import os, json, struct, sys

# Reuse the library's meta.json schema check (parseCaptureMeta) if importable,
# else replicate minimally.
sys.path.insert(0, "/Users/matte/projects/browsercore/testing/src")
try:
    from golden.golden import parseCaptureMeta
    HAS_LIB = True
except Exception as e:
    HAS_LIB = False
    print(f"Note: could not import library golden loader ({e}); using local schema check")

CAPTURES = "/Users/matte/projects/browsercore/testing/captures"
ORACLE_OUT = os.path.join(CAPTURES, "_probe", "output")

SETTING_IDS_REV = {1:"HEADER_TABLE_SIZE",2:"ENABLE_PUSH",3:"MAX_CONCURRENT_STREAMS",
                   4:"INITIAL_WINDOW_SIZE",5:"MAX_FRAME_SIZE",6:"MAX_HEADER_LIST_SIZE",
                   8:"ENABLE_CONNECT_PROTOCOL",9:"NO_RFC7540_PRIORITIES"}

def parse_settings(data):
    # HTTP/2 frame: length(3)+type(1)+flags(1)+stream(4)
    assert len(data) >= 9, "settings frame too short"
    length = struct.unpack(">I", b'\x00'+data[0:3])[0]
    ftype = data[3]
    flags = data[4]
    stream = struct.unpack(">I", data[5:9])[0]
    assert ftype == 0x04, f"expected SETTINGS (0x04) got 0x{ftype:02x}"
    assert stream == 0, "SETTINGS must be on stream 0"
    payload = data[9:]
    assert len(payload) == length, f"payload len {len(payload)} != frame length {length}"
    settings = []
    for i in range(0, len(payload), 6):
        sid = struct.unpack(">H", payload[i:i+2])[0]
        val = struct.unpack(">I", payload[i+2:i+6])[0]
        settings.append((SETTING_IDS_REV.get(sid, f"UNKNOWN({sid})"), val))
    return {"flags": flags, "settings": settings}

def load_oracle_settings(oracle_name):
    for suffix in ["", "_fresh"]:
        p = os.path.join(ORACLE_OUT, f"{oracle_name}{suffix}.json")
        if os.path.exists(p):
            with open(p) as f: return json.load(f)
    return None

VALID_RECORDS = {"client_hello","settings","headers","server_hello"}
VALID_PROTOCOLS = {"tls","http2","http1","tcp"}
VALID_SOURCES = {"curl-impersonate","real-browser"}
VALID_REASONS = {"ephemeral_key","nonce","grease","random"}

def local_validate_meta(meta, path):
    assert meta["source"] in VALID_SOURCES, f"bad source {meta['source']}"
    assert meta["protocol"] in VALID_PROTOCOLS, f"bad protocol {meta['protocol']}"
    assert meta["record"] in VALID_RECORDS, f"bad record {meta['record']}"
    assert isinstance(meta["description"], str)
    assert isinstance(meta["createdAt"], str)
    assert isinstance(meta["profile"], str)
    for rf in meta["randomizedFields"]:
        assert rf["reason"] in VALID_REASONS
        assert isinstance(rf["byteOffset"], int) and rf["byteOffset"] >= 0
        assert isinstance(rf["length"], int) and rf["length"] >= 0

PROFILES = [("chrome-131","chrome131"), ("firefox-133","firefox133"), ("safari-17","safari170")]
all_ok = True
for gname, oracle in PROFILES:
    print(f"\n=== {gname} ===")
    # Validate meta.json schema (both local and library if available)
    for proto in ["tls","http2"]:
        mp = os.path.join(CAPTURES, gname, proto, "client_hello.meta.json" if proto=="tls" else "settings.meta.json")
        with open(mp) as f: meta = json.load(f)
        try:
            local_validate_meta(meta, mp)
            if HAS_LIB:
                parseCaptureMeta(meta, f"{gname}/{proto}/{'client_hello' if proto=='tls' else 'settings'}")
            print(f"  {proto} meta.json: SCHEMA OK")
        except Exception as e:
            print(f"  {proto} meta.json: SCHEMA FAIL: {e}")
            all_ok = False
    # Validate settings frame
    sp = os.path.join(CAPTURES, gname, "http2", "settings.bin")
    with open(sp,"rb") as f: sdata=f.read()
    parsed = parse_settings(sdata)
    od = load_oracle_settings(oracle)
    oracle_settings = od["http2"]["sent_frames"][0]["settings"]  # first SETTINGS
    # Compare
    oracle_pairs = [tuple(s.split(" = ",1)) for s in oracle_settings]
    parsed_pairs = [(k,str(v)) for k,v in parsed["settings"]]
    oracle_pairs_str = [(k,str(v)) for k,v in oracle_pairs]
    if parsed_pairs == oracle_pairs_str:
        print(f"  settings.bin: MATCHES oracle ({len(parsed_pairs)} settings)")
    else:
        print(f"  settings.bin: MISMATCH")
        print(f"    parsed:   {parsed_pairs}")
        print(f"    oracle:   {oracle_pairs_str}")
        all_ok = False
print(f"\n{'ALL VALID' if all_ok else 'VALIDATION FAILED'}")
