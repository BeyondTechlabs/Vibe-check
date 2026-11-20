"""Build a tiny binary AndroidManifest.xml (AXML) for tests, standard library only."""
import struct

NS = "http://schemas.android.com/apk/res/android"


def encode(elements):
    """elements: list of (depth_change, tag, [(name, value)]) where value is str or bool; depth_change -1 closes."""
    strings = [NS, "android"]
    def idx(s):
        if s not in strings:
            strings.append(s)
        return strings.index(s)
    body = b""
    for kind, tag, attrs in elements:
        if kind == "end":
            body += struct.pack("<HHIIIII", 0x0103, 16, 24, 1, 0xFFFFFFFF, 0xFFFFFFFF, idx(tag))
            continue
        ab = b""
        for name, val in attrs:
            if isinstance(val, bool):
                ab += struct.pack("<IIIHBBI", idx(NS), idx(name), 0xFFFFFFFF, 8, 0, 0x12, 0xFFFFFFFF if val else 0)
            else:
                ab += struct.pack("<IIIHBBI", idx(NS), idx(name), idx(val), 8, 0, 0x03, idx(val))
        head = struct.pack("<IIIIHHHHHH", 1, 0xFFFFFFFF, 0xFFFFFFFF, idx(tag), 20, 20, len(attrs), 0, 0, 0)
        chunk = head + ab
        body += struct.pack("<HHI", 0x0102, 16, 8 + len(chunk)) + chunk
    enc = []
    for s in strings:
        u = s.encode("utf-16-le")
        enc.append(struct.pack("<H", len(s)) + u + b"\x00\x00")
    offs, pos = [], 0
    for e in enc:
        offs.append(pos); pos += len(e)
    sdata = b"".join(enc)
    sdata += b"\x00" * ((4 - len(sdata) % 4) % 4)
    hsize = 28
    sstart = hsize + 4 * len(strings)
    pool = struct.pack("<HHIIIIII", 0x0001, hsize, sstart + len(sdata), len(strings), 0, 0, sstart, 0) + struct.pack("<%dI" % len(strings), *offs) + sdata
    total = 8 + len(pool) + len(body)
    return struct.pack("<HHI", 0x0003, 8, total) + pool + body
