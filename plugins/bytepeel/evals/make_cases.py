#!/usr/bin/env python3
"""Generates the eval cases in this directory: inputs, prompts and graders.

Every expected answer is computed here with the Python standard library, not
with bytepeel, so the suite can't inherit a bytepeel bug. Run it from anywhere:

    python3 plugins/bytepeel/evals/make_cases.py

It rewrites every case directory it owns (those listed in CASES) and leaves
the rest alone. The output is deterministic.
"""
import base64
import gzip
import json
import random
import re
import shutil
import struct
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
CERT_PEM = (ROOT / "crates/bytepeel-core/tests/fixtures/isrg-root-x2.pem").read_text()

FOOTER = "\n\nEnd your reply with one line in exactly this form:\n\nANSWER: {form}\n"


# --- encoders ---------------------------------------------------------------

def varint(n):
    n &= (1 << 64) - 1
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def key(field, wt):
    return varint(field << 3 | wt)


def pb_varint(field, n):
    return key(field, 0) + varint(n)


def pb_len(field, data):
    if isinstance(data, str):
        data = data.encode()
    return key(field, 2) + varint(len(data)) + data


def pb_fixed64(field, raw8):
    return key(field, 1) + raw8


def zigzag(n):
    return (n << 1) ^ (n >> 63)


def cbor_head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    for ai, fmt in ((24, ">B"), (25, ">H"), (26, ">I"), (27, ">Q")):
        if n < 1 << (8 * struct.calcsize(fmt)):
            return bytes([major << 5 | ai]) + struct.pack(fmt, n)
    raise ValueError(n)


def cbor(v):
    if v is True:
        return b"\xf5"
    if isinstance(v, int):
        return cbor_head(0, v) if v >= 0 else cbor_head(1, -1 - v)
    if isinstance(v, bytes):
        return cbor_head(2, len(v)) + v
    if isinstance(v, str):
        return cbor_head(3, len(v.encode())) + v.encode()
    if isinstance(v, list):
        return cbor_head(4, len(v)) + b"".join(cbor(x) for x in v)
    if isinstance(v, dict):
        return cbor_head(5, len(v)) + b"".join(cbor(k) + cbor(x) for k, x in v.items())
    if isinstance(v, tuple) and v[0] == "tag":
        return cbor_head(6, v[1]) + cbor(v[2])
    raise TypeError(v)


def msgpack_str(s):
    b = s.encode()
    assert len(b) < 32
    return bytes([0xA0 | len(b)]) + b


def spaced(b):
    return " ".join(f"{x:02x}" for x in b)


def xxd(b):
    lines = []
    for off in range(0, len(b), 16):
        chunk = b[off:off + 16]
        groups = " ".join(chunk[i:i + 2].hex() for i in range(0, len(chunk), 2))
        text = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        lines.append(f"{off:08x}: {groups:<39}  {text}")
    return "\n".join(lines)


def gz(data):
    return gzip.compress(data, mtime=0)


def der_from_pem(pem):
    body = "".join(l for l in pem.splitlines() if l and not l.startswith("-----"))
    return base64.b64decode(body)


# --- graders ----------------------------------------------------------------

def answer(pattern, name="answer", flags="i"):
    """A regex grader on the ANSWER line. `pattern` is matched right after it;
    END after it allows a closing backtick and nothing else."""
    g = {"type": "regex", "pattern": r"ANSWER:\s*`?" + pattern}
    if flags:
        g["flags"] = flags
    return name, g


END = r"`?\s*$"


def tool_indicator(tool):
    """Whether the run actually called bytepeel's MCP tool (not scored; the
    no-plugin arm doesn't have it)."""
    return "used-bytepeel", {"type": "tool_used", "tool": f"mcp__plugin_bytepeel_bytepeel__{tool}", "arm": "with-only"}


def esc(s):
    return re.escape(s)


# --- cases ------------------------------------------------------------------

CASES = {}


def case(name, prompt, form, graders, tags=()):
    tool = "set" if "edit" in tags else "peel"
    CASES[name] = (prompt + FOOTER.format(form=form), list(graders) + [tool_indicator(tool)], list(tags))


# Protobuf: int64 -300 is a 10-byte varint.
m = pb_varint(1, -300) + pb_len(2, "alice") + pb_varint(3, 1700000000)
case(
    "pb-negative-int64",
    f"This is a protobuf message I pulled out of a gRPC log, as hex. We don't have the .proto, but field 1 is an `int64` account balance in cents.\n\n```\n{m.hex()}\n```\n\nWhat is the balance in field 1?",
    "<the integer value of field 1>",
    [answer(r"-300\b")],
    ["protobuf", "varint"],
)

# Protobuf: sint32 uses zigzag.
m = pb_len(1, "probe-7") + pb_varint(2, 42) + pb_varint(3, zigzag(-150))
case(
    "pb-sint32-zigzag",
    f"Protobuf message (hex) from a sensor. Field 3 is declared `sint32 temperature_offset`.\n\n```\n{m.hex()}\n```\n\nWhat is the temperature offset?",
    "<the integer value of field 3>",
    [answer(r"-150\b")],
    ["protobuf", "varint"],
)

# Protobuf: packed repeated varints.
vals = [3, 270, 86942, 1]
m = pb_len(1, "batch") + pb_len(4, b"".join(varint(v) for v in vals))
case(
    "pb-packed-varints",
    f"This protobuf message (base64) has a `repeated uint32 ids = 4 [packed=true]` field.\n\n```\n{base64.b64encode(m).decode()}\n```\n\nList the ids in field 4, in order.",
    "<comma-separated list>",
    [answer(r"\[?3,\s*270,\s*86942,\s*1\]?" + END)],
    ["protobuf", "base64"],
)

# Protobuf: double in a fixed64.
m = pb_len(1, "rate") + pb_fixed64(5, struct.pack("<d", 0.0725))
case(
    "pb-double",
    f"Protobuf (hex). Field 5 is a `double`.\n\n```\n{spaced(m)}\n```\n\nWhat is the value of field 5?",
    "<the number>",
    [answer(r"0?\.0725(0*)?\b")],
    ["protobuf", "fixed64"],
)

# Protobuf: fixed64 above 2^53 needs exact integer handling.
big = 2**53 + 1
m = pb_fixed64(6, struct.pack("<Q", big)) + pb_len(7, "order")
case(
    "pb-fixed64-above-2-53",
    f"Field 6 of this protobuf message is a `fixed64` order id. Hex:\n\n```\n{m.hex()}\n```\n\nWhat is the order id, exactly?",
    "<the decimal integer>",
    [answer(str(big) + r"\b")],
    ["protobuf", "fixed64"],
)

# Base64url without padding, with - and _ in it.
raw = bytes.fromhex("fbefbe0f3ffe7f00a1b2c3d4e5f6f7fffe1001")
b64u = base64.urlsafe_b64encode(raw).decode().rstrip("=")
assert "-" in b64u and "_" in b64u and len(raw) % 3
case(
    "base64url-no-padding",
    f"This token segment is URL-safe base64 with the padding stripped:\n\n```\n{b64u}\n```\n\nWhat are the decoded bytes, as lowercase hex with no spaces?",
    "<hex>",
    [answer(raw.hex() + r"\b")],
    ["base64"],
)

# base64 -> gzip -> JSON.
doc = b'{"user":"m.lindqvist","roles":["admin","ops"],"session":{"id":"9c1e7f02-55aa-4d3b-8e0f-6b2d1c9a4e77","ttl":3600}}'
b64 = base64.b64encode(gz(doc)).decode()
case(
    "base64-gzip-json",
    f"This value was in a `X-Session-State` header:\n\n```\n{b64}\n```\n\nWhat is the session id inside it?",
    "<the session id>",
    [answer(r"9c1e7f02-55aa-4d3b-8e0f-6b2d1c9a4e77\b")],
    ["base64", "gzip"],
)

# Protobuf whose string field holds base64 of another protobuf.
inner = pb_varint(1, 1234567) + pb_len(2, "ops@example.org")
outer = pb_len(1, "v2") + pb_len(2, base64.b64encode(inner).decode()) + pb_varint(3, 1)
case(
    "pb-nested-base64-pb",
    f"A message from our queue (hex). Field 2 carries the original request, which our producer serializes separately before putting it there.\n\n```\n{outer.hex()}\n```\n\nWhat is the user id (field 1) of the original request?",
    "<the integer>",
    [answer(r"1234567\b")],
    ["protobuf", "nested"],
)

# hex -> zlib -> protobuf.
m = pb_varint(1, 7) + pb_len(2, "eu-north-1b") + pb_len(3, pb_varint(1, 443) + pb_len(2, "h2"))
case(
    "hex-zlib-pb",
    f"Blob from a cache entry, hex:\n\n```\n{zlib.compress(m, 9).hex()}\n```\n\nWhat port number is in it? (It's field 1 of the submessage in field 3.)",
    "<the integer>",
    [answer(r"443\b")],
    ["zlib", "protobuf"],
)

# xxd dump of a protobuf with a nested message.
m = (pb_len(1, "device-config/v3") + pb_varint(2, 1) +
     pb_len(7, pb_len(1, "wlan0") + pb_varint(2, 1500) + pb_varint(3, 0)) +
     pb_len(7, pb_len(1, "eth0") + pb_varint(2, 9000) + pb_varint(3, 1)))
case(
    "xxd-pb-repeated",
    f"`xxd` output of a protobuf config file:\n\n```\n{xxd(m)}\n```\n\nField 7 is a repeated interface entry (field 1 name, field 2 MTU). What is the MTU of the second interface?",
    "<the integer>",
    [answer(r"9000\b")],
    ["protobuf", "xxd"],
)

# CBOR: negative integers are -1-n.
c = cbor({"id": -1000, "ts": ("tag", 1, 1700000000), "blob": bytes.fromhex("cafebabe"), "ok": True})
case(
    "cbor-negative-int",
    f"CBOR (hex) from a device:\n\n```\n{c.hex()}\n```\n\nWhat is the value of the `id` key?",
    "<the integer>",
    [answer(r"-1000\b")],
    ["cbor"],
)

# MessagePack: uint64 above 2^63.
mp = b"\x82" + msgpack_str("counter") + b"\xcf" + struct.pack(">Q", 2**64 - 2) + msgpack_str("node") + msgpack_str("b7")
case(
    "msgpack-uint64",
    f"MessagePack (base64):\n\n```\n{base64.b64encode(mp).decode()}\n```\n\nWhat is the exact value of `counter`?",
    "<the decimal integer>",
    [answer(str(2**64 - 2) + r"\b")],
    ["msgpack"],
)

# JWT: a control case most agents should get right either way.
def b64u_json(s):
    return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")
jwt = ".".join([
    b64u_json('{"alg":"ES256","typ":"JWT","kid":"k-2026-03"}'),
    b64u_json('{"sub":"svc-billing","aud":["api","admin"],"exp":1767225600,"scope":"invoices:write"}'),
    "MEUCIQD1x1s4Tg2kV0QhH5aV1Ylb4cF3d9bJ7gq0t5pZb8Q3pAIgYc2xq1o9N1Ns0l1nOe6b3k7hJ8m2b5p6x0rT4k9l2aE",
])
case(
    "jwt-claims",
    f"Here's a bearer token from a failing request:\n\n```\n{jwt}\n```\n\nWhat is its `sub` claim and its expiry as a UTC date (YYYY-MM-DD)?",
    "<sub> <YYYY-MM-DD>",
    [answer(r"svc-billing\s*,?\s*2026-01-01\b")],
    ["jwt", "control"],
)

# PEM certificate: serial number.
case(
    "pem-cert-serial",
    f"What's the serial number of this certificate, in hex?\n\n```\n{CERT_PEM.strip()}\n```",
    "<hex serial, no colons>",
    [answer(r"(0x)?41:?d2:?9d:?d1:?72:?ea:?ee:?a7:?80:?c1:?2c:?6c:?e9:?2f:?87:?52\b")],
    ["der", "pem"],
)

# Raw DER certificate inside a protobuf bytes field.
der = der_from_pem(CERT_PEM)
m = pb_len(1, "trust-anchor") + pb_len(2, der) + pb_varint(3, 2)
case(
    "pb-embedded-der-cert",
    f"This protobuf message (base64) stores a trust anchor; field 2 holds the certificate.\n\n```\n{base64.b64encode(m).decode()}\n```\n\nWhen does the certificate expire? Give the notAfter date.",
    "<YYYY-MM-DD>",
    [answer(r"2040-09-17\b")],
    ["protobuf", "der", "nested"],
)

# Gzip with a bad CRC.
g = bytearray(gz(b"backup-manifest v1\n" + b"chunk=0001 sha=4b2a\n" * 12))
g[-8] ^= 0x01  # CRC32 trailer
case(
    "gzip-bad-crc",
    f"This base64 came out of a backup index. Is the compressed data intact, or is it damaged?\n\n```\n{base64.b64encode(bytes(g)).decode()}\n```",
    "intact | damaged",
    [answer(r"damaged\b")],
    ["gzip", "integrity"],
)

# Edit: protobuf, the parent length changes.
m = bytes.fromhex("0a05616c6963651a03089601")
case(
    "edit-pb-varint",
    f"Here is a protobuf message as spaced hex:\n\n```\n{spaced(m)}\n```\n\nSet field 1 inside the submessage in field 3 to 300000. Give the whole updated message in the same hex format.",
    "<the updated hex>",
    [answer(esc("0a 05 61 6c 69 63 65 1a 04 08 e0 a7 12") + END)],
    ["edit", "protobuf"],
)

# Edit: three levels of lengths change, base64 in and out.
def env(region):
    return pb_len(1, "svc") + pb_len(2, pb_varint(1, 1) + pb_len(3, pb_len(1, "db") + pb_len(3, region)))
before, after = env("dev"), env("production")
case(
    "edit-pb-nested-base64",
    f"This base64 protobuf is a deploy descriptor:\n\n```\n{base64.b64encode(before).decode()}\n```\n\nThe string at field 2 → field 3 → field 3 is currently \"dev\". Change it to \"production\" and give me the new base64.",
    "<the base64>",
    [answer(esc(base64.b64encode(after).decode()) + END, flags="")],
    ["edit", "protobuf", "base64"],
)

# Edit: CBOR integer width changes.
before = cbor({"name": "cache", "ttl": 60, "tags": ["a"]})
after = cbor({"name": "cache", "ttl": 86400, "tags": ["a"]})
case(
    "edit-cbor-int-width",
    f"CBOR config (hex):\n\n```\n{before.hex()}\n```\n\nChange `ttl` to 86400 and give the new CBOR as hex.",
    "<the hex>",
    [answer(after.hex() + END)],
    ["edit", "cbor"],
)


# --- realistic-size cases ---------------------------------------------------
# Hundreds of bytes to a few KB, like real payloads. Values come from a seeded
# generator so the cases are stable.

def mp(v):
    """Minimal MessagePack encoder (canonical widths)."""
    if v is None:
        return b"\xc0"
    if v is True or v is False:
        return b"\xc3" if v else b"\xc2"
    if isinstance(v, int):
        if 0 <= v < 128:
            return bytes([v])
        if -32 <= v < 0:
            return struct.pack(">b", v)
        if v >= 0:
            for tag, fmt in ((0xCC, ">B"), (0xCD, ">H"), (0xCE, ">I"), (0xCF, ">Q")):
                if v < 1 << (8 * struct.calcsize(fmt)):
                    return bytes([tag]) + struct.pack(fmt, v)
        for tag, fmt in ((0xD0, ">b"), (0xD1, ">h"), (0xD2, ">i"), (0xD3, ">q")):
            bits = 8 * struct.calcsize(fmt)
            if -(1 << (bits - 1)) <= v:
                return bytes([tag]) + struct.pack(fmt, v)
    if isinstance(v, float):
        return b"\xcb" + struct.pack(">d", v)
    if isinstance(v, str):
        b = v.encode()
        if len(b) < 32:
            return bytes([0xA0 | len(b)]) + b
        return b"\xd9" + bytes([len(b)]) + b
    if isinstance(v, list):
        assert len(v) < 65536
        head = bytes([0x90 | len(v)]) if len(v) < 16 else b"\xdc" + struct.pack(">H", len(v))
        return head + b"".join(mp(x) for x in v)
    if isinstance(v, dict):
        assert len(v) < 16
        return bytes([0x80 | len(v)]) + b"".join(mp(k) + mp(x) for k, x in v.items())
    raise TypeError(v)


def wrap(s, n=76):
    return "\n".join(s[i:i + n] for i in range(0, len(s), n))


rng = random.Random(365)

# Telemetry batch: repeated readings with fixed64 timestamps, doubles, sint32.
readings = []
for i in range(14):
    readings.append({
        "ts": 1767225600000 + i * 15000 + rng.randrange(1000),
        "value": round(rng.uniform(95, 110), 2),
        "delta": rng.randrange(-40, 40),
        "unit": "kPa",
        "sensor": 0xA0000000 + rng.randrange(1 << 20),
    })
lo = min(readings, key=lambda r: r["delta"])
assert sum(r["delta"] == lo["delta"] for r in readings) == 1
m = pb_len(1, "plant-7/line-B") + pb_varint(2, 3) + b"".join(
    pb_len(3, pb_fixed64(1, struct.pack("<Q", r["ts"])) + pb_fixed64(2, struct.pack("<d", r["value"]))
           + pb_varint(3, zigzag(r["delta"])) + pb_len(4, r["unit"]) + key(5, 5) + struct.pack("<I", r["sensor"]))
    for r in readings)
case(
    "large-pb-telemetry",
    f"A telemetry batch from our ingest queue, base64-encoded protobuf. No .proto, but we know field 3 is a repeated reading with: 1 = fixed64 timestamp (ms since epoch), 2 = double pressure, 3 = sint32 delta, 4 = string unit, 5 = fixed32 sensor id.\n\n```\n{wrap(base64.b64encode(m).decode())}\n```\n\nWhich reading has the lowest delta? Give its timestamp and its pressure value.",
    "<timestamp> <pressure>",
    [answer(f"{lo['ts']}" + r"\D{1,20}" + re.escape(repr(lo["value"])).rstrip("0") + r"0*\b")],
    ["large", "protobuf", "fixed64"],
)

# Packed fixed64 ids above 2^53.
ids = [(1 << 60) + rng.randrange(1 << 59) for _ in range(20)]
m = pb_len(1, "shard-0042") + pb_len(2, b"".join(struct.pack("<Q", x) for x in ids)) + pb_varint(3, len(ids))
case(
    "large-pb-packed-fixed64",
    f"Protobuf message (hex). Field 2 is `repeated fixed64 object_ids` (packed).\n\n```\n{m.hex()}\n```\n\nWhat is the 13th object id (1-based)? Give it exactly.",
    "<the decimal integer>",
    [answer(str(ids[12]) + r"\b")],
    ["large", "protobuf", "fixed64"],
)

# 2 KB base64 of gzip of JSON: a script handles this fine (control).
users = [{"id": 10400 + i, "name": f"user{i:03d}", "roles": ["viewer"] + (["editor"] if i % 3 == 0 else []),
          "mfa": i % 4 != 1, "last_login": 1760000000 + rng.randrange(5000000)} for i in range(60)]
users[37]["roles"].append("breakglass")
doc = json.dumps({"tenant": "acme-eu", "users": users}, separators=(",", ":")).encode()
case(
    "large-base64-gzip-json",
    f"This came out of a `state` cookie (base64):\n\n```\n{wrap(base64.b64encode(gz(doc)).decode())}\n```\n\nWhich user has the `breakglass` role? Give their id.",
    "<id>",
    [answer(r"10437\b")],
    ["large", "gzip", "control"],
)

# gzip'd protobuf inventory with negative int32 quantities (10-byte varints).
items = []
for i in range(36):
    sku = f"{rng.choice('ABCDEFGH')}{rng.choice('XYZ')}-{rng.randrange(1000, 9999)}"
    items.append((sku, rng.randrange(-20, 400), rng.randrange(100, 99999)))
items[22] = ("AX-4471", -3, 129900)
m = pb_len(1, "warehouse-oslo-2") + b"".join(
    pb_len(2, pb_len(1, s) + pb_varint(2, q) + pb_varint(3, c)) for s, q, c in items)
case(
    "large-gzip-pb-inventory",
    f"Inventory snapshot from a cache, base64 of gzip of protobuf. Field 2 is a repeated item: 1 = sku (string), 2 = quantity (int32), 3 = price in cents (int64).\n\n```\n{wrap(base64.b64encode(gz(m)).decode())}\n```\n\nWhat is the quantity of sku AX-4471?",
    "<the integer>",
    [answer(r"-3\b")],
    ["large", "gzip", "protobuf", "varint"],
)

# MessagePack event log with mixed integer widths and floats.
events = []
for i in range(48):
    events.append({"seq": 1000 + i, "t": round(1767225600 + i * 2.5 + rng.random(), 3),
                   "dev": f"edge-{rng.randrange(1, 9)}", "v": rng.choice([rng.randrange(-30, 0), rng.randrange(-30000, -129), rng.randrange(-3000000, -40000), rng.randrange(0, 70000)])})
events[17]["v"] = -31337
m = mp({"src": "edge-gw", "events": events})
case(
    "large-msgpack-events",
    f"MessagePack event log (base64):\n\n```\n{wrap(base64.b64encode(m).decode())}\n```\n\nWhat are `v` and `t` for the event with `seq` 1017?",
    "<v> <t>",
    [answer(r"-31337\D{1,20}" + re.escape(repr(events[17]["t"])) + r"0*\b")],
    ["large", "msgpack"],
)

# CBOR envelope whose byte string holds protobuf.
inner = pb_len(1, "order-7f3k") + pb_varint(2, 4) + pb_len(3, pb_len(1, "SE") + pb_len(2, "Göteborg") + pb_varint(3, 41258))
env_ = cbor({"v": 2, "kid": "kms/eu/17", "iat": ("tag", 1, 1767300000), "nonce": bytes(range(16)),
             "payload": inner, "meta": {"retries": 0, "lag_ms": -12, "route": ["edge", "core", "billing"]}})
case(
    "large-cbor-envelope-pb",
    f"A message envelope (CBOR, hex). Its `payload` is a protobuf order record whose field 3 is the shipping address (1 country, 2 city, 3 postal code).\n\n```\n{env_.hex()}\n```\n\nWhat is the city and the postal code?",
    "<city> <postal code>",
    [answer(r"G(ö|o)teborg\D{1,20}41258\b")],
    ["large", "cbor", "protobuf", "nested"],
)

# xxd dump of protobuf with float32 fields.
axes = [("x-axis", 0.5, 1.25), ("y-axis", -2.0, 0.75), ("z-axis", -12.25, 3.5), ("pitch", 0.125, -6.0), ("roll", 7.75, 0.0625)]
m = pb_len(1, "imu-calibration") + pb_varint(2, 20261115) + b"".join(
    pb_len(3, pb_len(1, n) + key(2, 5) + struct.pack("<f", a) + key(3, 5) + struct.pack("<f", b) + pb_varint(4, i))
    for i, (n, a, b) in enumerate(axes)) + pb_len(9, bytes(rng.randrange(256) for _ in range(64)))
case(
    "large-xxd-pb-floats",
    f"xxd of a calibration blob (protobuf). Field 3 entries are: 1 = axis name, 2 = float offset, 3 = float scale.\n\n```\n{xxd(m)}\n```\n\nWhat is the offset (field 2) for the z-axis entry?",
    "<the number>",
    [answer(r"-12\.250*\b")],
    ["large", "protobuf", "xxd"],
)

# gRPC -bin metadata: base64 protobuf with a JWT inside.
jwt2 = ".".join([
    b64u_json('{"alg":"RS256","kid":"2026-q4"}'),
    b64u_json('{"iss":"https://auth.example.net","sub":"agent-runner-12","exp":1795132800,"cnf":{"x5t#S256":"Yz9mS2xPaVBfY0ZrQ3hD"}}'),
    base64.urlsafe_b64encode(bytes(rng.randrange(256) for _ in range(256))).decode().rstrip("="),
])
m = pb_len(1, "req-9f2c41") + pb_len(2, pb_len(1, "authorization") + pb_len(2, "Bearer " + jwt2)) + pb_varint(3, 1)
case(
    "large-grpc-bin-jwt",
    f"This is the value of a `x-auth-context-bin` gRPC metadata header:\n\n```\n{base64.b64encode(m).decode()}\n```\n\nWhose token is it (`sub`), and when does it expire (UTC date, YYYY-MM-DD)?",
    "<sub> <YYYY-MM-DD>",
    [answer(r"agent-runner-12\s*,?\s*2026-11-20\b")],
    ["large", "protobuf", "jwt", "nested"],
)

# Edit: a deep change in a larger protobuf, several lengths change.
def manifest(replicas, image):
    containers = (pb_len(1, "api") + pb_len(2, image) + pb_varint(3, 8080) +
                  pb_len(4, pb_len(1, "LOG_LEVEL") + pb_len(2, "info")) +
                  pb_len(4, pb_len(1, "REGION") + pb_len(2, "eu-north-1")))
    sidecar = pb_len(1, "envoy") + pb_len(2, "envoyproxy/envoy:v1.32.1") + pb_varint(3, 9901)
    spec = pb_varint(1, replicas) + pb_len(2, containers) + pb_len(2, sidecar) + pb_len(5, "rolling")
    return pb_len(1, "payments-api") + pb_len(2, "prod") + pb_len(3, spec) + pb_len(15, bytes(range(40)))
before = manifest(3, "registry.example.net/payments/api:2026.11.2")
after = manifest(300, "registry.example.net/payments/api:2026.11.14-hotfix.1")
case(
    "large-edit-pb-manifest",
    f"Deploy manifest, base64 protobuf:\n\n```\n{base64.b64encode(before).decode()}\n```\n\nField 3 is the spec: 3.1 is replicas, and each 3.2 is a container whose field 2 is its image. Set replicas to 300, and change the first container's image to `registry.example.net/payments/api:2026.11.14-hotfix.1`. Give me the new base64.",
    "<the base64>",
    [answer(esc(base64.b64encode(after).decode()) + END, flags="")],
    ["large", "edit", "protobuf", "base64"],
)

# Edit: MessagePack integer widens.
def quota(limit):
    return mp({"tenant": "acme-eu", "plan": "pro", "limit": limit, "burst": 250, "windows": [60, 3600, 86400],
               "owners": ["ops@acme.example", "sre@acme.example"], "soft": True})
case(
    "large-edit-msgpack",
    f"Quota record, MessagePack as base64:\n\n```\n{base64.b64encode(quota(100)).decode()}\n```\n\nRaise `limit` to 70000 and give the new base64.",
    "<the base64>",
    [answer(esc(base64.b64encode(quota(70000)).decode()) + END, flags="")],
    ["large", "edit", "msgpack"],
)


# --- writer -----------------------------------------------------------------

def yaml_scalar(v):
    if isinstance(v, (int, float)):
        return str(v)
    return "'" + str(v).replace("'", "''") + "'"


def main():
    for name, (prompt, graders, tags) in CASES.items():
        d = HERE / name
        if d.exists():
            shutil.rmtree(d)
        (d / "graders").mkdir(parents=True)
        head = ["---", "max_turns: 20", "timeout_seconds: 300", f"tags: [{', '.join(tags)}]", "---", ""]
        (d / "prompt.md").write_text("\n".join(head) + prompt)
        for gname, g in graders:
            lines = ["---"] + [f"{k}: {yaml_scalar(v)}" for k, v in g.items()] + ["---", ""]
            (d / "graders" / f"{gname}.md").write_text("\n".join(lines))
    print(f"{len(CASES)} cases")


if __name__ == "__main__":
    main()
