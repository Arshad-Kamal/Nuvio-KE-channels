#!/usr/bin/env python3
"""Egress-IP leak check (Nuvio-Project Spec 60 D12): fails when published text holds the IP this machine fetches from.

A token minted by a broadcaster for our research fetch embedded the household IP as a decimal uint32, so the check
covers every form seen or cheaply guessable: dotted with '.', '-' or '_' separators and leading zeros, in either
octet order; zero-padded octets run together (203000113007); decimal and hex in both byte orders (hex also as an
IPv4-mapped IPv6 pair, cb00:7107, and as separated octets, cb-00-71-07), in the raw text, its URL-decoded layers,
and every base64/base64url run of 6+ characters and hex run of 8+ digits decoded at each alignment (raw 4-byte forms
are searched there too). The IP is looked up at run time (IPv4; this machine has no IPv6 route) and recorded
in a local state file outside every repo, so an address the dynamic WAN had before stays checked.

Usage: egress.py PATH... | -     scans files (directories recursively, .git skipped) or stdin (e.g. `git log -p`);
                                 exit 0 clean, 1 on a hit (location and form, never the IP), 2 when no lookup answered.
"""
import base64
import binascii
import ipaddress
import os
import re
import sys
import urllib.request
from pathlib import Path
from urllib.parse import unquote_to_bytes

LOOKUPS = ("https://api.ipify.org", "https://checkip.amazonaws.com")
STATE = Path(os.environ.get("NUVIO_EGRESS_STATE") or "~/.local/state/nuvio-ke-channels/egress-ips").expanduser()
BASE64_RUN = re.compile(rb"[A-Za-z0-9+/_-]{6,}")  # 6 = four raw bytes
HEX_RUN = re.compile(rb"[0-9A-Fa-f]{8,}")  # 8 = four raw bytes
URL_DECODE_LAYERS = 3


class LookupFailed(Exception):
    pass


def lookup() -> set[str]:
    """The current IPv4 egress address(es) from independent services; raises LookupFailed when none answers."""
    found = set()
    for url in LOOKUPS:
        try:
            with urllib.request.urlopen(url, timeout=15) as response:
                found.add(str(ipaddress.IPv4Address(response.read(64).decode("ascii").strip())))
        except (OSError, ValueError) as error:  # URLError is an OSError; a non-IP body is a ValueError
            print(f"egress lookup {url} failed: {error}", file=sys.stderr)
    if not found:
        raise LookupFailed("no egress IP lookup answered; refusing to publish unchecked")
    return found


def known_ips() -> set[str]:
    """The current egress IPs plus every one recorded before; records the current ones."""
    current = lookup()
    recorded = set(STATE.read_text(encoding="ascii").split()) if STATE.exists() else set()
    if not current <= recorded:
        STATE.parent.mkdir(parents=True, exist_ok=True)
        STATE.write_text("\n".join(sorted(current | recorded)) + "\n", encoding="ascii")
    return current | recorded


class Needles:
    """The searchable forms of one IPv4 address."""

    def __init__(self, ip: str):
        packed = ipaddress.IPv4Address(ip).packed
        big, little = int.from_bytes(packed, "big"), int.from_bytes(packed, "little")

        def dotted(octets: bytes) -> re.Pattern:
            return re.compile(rb"(?<!\d)" + rb"[._-]".join(b"0*%d" % octet for octet in octets) + rb"(?!\d)")

        self.text = [
            ("dotted", dotted(packed)),
            ("dotted-reversed", dotted(packed[::-1])),
            ("octets-padded", re.compile(b"%03d%03d%03d%03d" % tuple(packed))),
            ("decimal", re.compile(b"%d" % big)),
            ("decimal-le", re.compile(b"%d" % little)),
            ("hex", re.compile(b"0*%x(?:%04x|:0*%x)" % (big >> 16, big & 0xFFFF, big & 0xFFFF), re.IGNORECASE)),
            ("hex-octets", re.compile(rb"[.:_-]".join(b"%02x" % octet for octet in packed), re.IGNORECASE)),
            ("hex-le", re.compile(b"%x" % little, re.IGNORECASE)),
        ]
        self.raw = [("raw", packed), ("raw-le", packed[::-1])]


def _decoded_runs(layer: bytes):
    for run in HEX_RUN.findall(layer):
        for skip in range(2):
            chunk = run[skip:]
            yield bytes.fromhex(chunk[: len(chunk) // 2 * 2].decode("ascii"))
    for run in BASE64_RUN.findall(layer):
        standard = run.replace(b"-", b"+").replace(b"_", b"/")
        for skip in range(4):
            chunk = standard[skip:]
            if len(chunk) % 4 == 1:  # one leftover character encodes no whole byte
                chunk = chunk[:-1]
            chunk += b"=" * (-len(chunk) % 4)
            try:
                yield base64.b64decode(chunk, validate=True)
            except binascii.Error:
                continue


def find(text: str, needles: list[Needles]) -> list[str]:
    """The forms of any needle IP found in the text (empty when clean)."""
    layers = [text.encode("utf-8", "surrogateescape")]
    for _ in range(URL_DECODE_LAYERS):
        decoded = unquote_to_bytes(layers[-1])
        if decoded == layers[-1]:
            break
        layers.append(decoded)
    hits = []
    for needle in needles:
        for layer in layers:
            hits += [form for form, pattern in needle.text if pattern.search(layer)]
            for decoded in _decoded_runs(layer):
                hits += [f"decoded:{form}" for form, pattern in needle.text if pattern.search(decoded)]
                hits += [f"decoded:{form}" for form, raw in needle.raw if raw in decoded]
    return sorted(set(hits))


def _files(paths: list[str]):
    for name in paths:
        path = Path(name)
        if path.is_dir():
            yield from (p for p in sorted(path.rglob("*")) if p.is_file() and ".git" not in p.parts)
        else:
            yield path


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        needles = [Needles(ip) for ip in known_ips()]
    except LookupFailed as error:
        print(error, file=sys.stderr)
        return 2
    sources = [("stdin", sys.stdin.read())] if sys.argv[1:] == ["-"] else [
        (str(p), p.read_bytes().decode("utf-8", "surrogateescape")) for p in _files(sys.argv[1:])]
    hits = 0
    for where, content in sources:
        for number, line in enumerate(content.splitlines(), 1):
            forms = find(line, needles)
            if forms:
                hits += 1
                print(f"EGRESS IP {where}:{number}: {', '.join(forms)}")
    print(f"egress check: {len(sources)} sources, {len(needles)} IPs, {hits} lines with a hit", file=sys.stderr)
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
