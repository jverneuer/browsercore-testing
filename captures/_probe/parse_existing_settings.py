#!/usr/bin/env python3
"""Parse the existing synthetic chrome-140 settings.bin to document what it actually contains."""
import struct
p="/Users/matte/projects/browsercore/testing/captures/chrome-140/http2/settings.bin"
with open(p,"rb") as f: d=f.read()
print(f"chrome-140 settings.bin: {len(d)} bytes, hex: {d.hex()}")
length=struct.unpack(">I", b'\x00'+d[0:3])[0]
ftype=d[3]; flags=d[4]; stream=struct.unpack(">I",d[5:9])[0]
print(f"frame: length={length} type=0x{ftype:02x} flags=0x{flags:02x} stream={stream}")
SETTING_IDS_REV = {1:"HEADER_TABLE_SIZE",2:"ENABLE_PUSH",3:"MAX_CONCURRENT_STREAMS",
                   4:"INITIAL_WINDOW_SIZE",5:"MAX_FRAME_SIZE",6:"MAX_HEADER_LIST_SIZE"}
for i in range(0,len(d)-9,6):
    sid=struct.unpack(">H", d[9+i:11+i])[0]
    val=struct.unpack(">I", d[11+i:15+i])[0]
    print(f"  setting {SETTING_IDS_REV.get(sid,sid)} = {val}")
