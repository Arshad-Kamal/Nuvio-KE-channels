"""The public gate (Nuvio-Project Spec 60 D12): a row that passes the private and NSFW rules is public only when
  iptv-org-url   its exact URL is in iptv-org's streams.json,
  fast-host      its host belongs to a FAST service i.mjh.nz indexes (Pluto, Samsung TV Plus, Roku, Plex),
  iptv-org-host  its host already serves a stream in iptv-org's streams.json, or
  reviewed-host  its host (or host/path prefix) is listed in reviewed-hosts.txt.
Anything else is private with reason "unreviewed-host"; adding an entry to reviewed-hosts.txt promotes its rows.

The two host criteria compare a tenant key, not a bare hostname: host[:port] (default ports dropped), plus the owner
path on a code or path-style storage host (raw.githubusercontent.com/<owner>), so one listed owner does not admit
every other owner. Hosts where anyone can publish under one name (shorteners, file shares, video platforms), hosts
named as proxies, URLs that carry another URL, and URLs shaped like Xtream's short form host/<user>/<pass>/<id>
(iptv-org lists such panel URLs, and one listed URL must not admit its siblings' logins) have no tenant: only an exact
iptv-org URL or a reviewed path admits them. Only iptv-org URLs that pass the URL deny rules vouch for a host (rules.vouches). A URL whose host or path
another parser could read differently (a backslash, non-ASCII or percent-encoded host; a dot segment or encoded
slash in the path) is admitted by nothing but an exact iptv-org URL.
"""
import json
import re
import urllib.request
from collections.abc import Callable
from pathlib import Path
from urllib.parse import unquote, urlsplit

IPTV_ORG_API = "https://iptv-org.github.io/api/"
IPTV_ORG_STREAMS = IPTV_ORG_API + "streams.json"
REVIEWED_HOSTS = Path(__file__).with_name("reviewed-hosts.txt")
MAX_DOWNLOAD = 64 << 20  # streams.json is ~4 MB; also the cap on every list the pool pulls (lists.fetch)

# i.mjh.nz's .channels.json indexes carry channel ids, not stream hosts, so the services' stream hosts are named here:
# the operator's redirectors (jmp2.uk, i./c.mjh.nz), Pluto, Plex, Roku, and the playout vendors Samsung TV Plus
# channels play from (amagi.tv, wurl; the hosts the Spec 60 research recorded for samsung-* channels).
FAST_SUFFIXES = ("jmp2.uk", "mjh.nz", "pluto.tv", "plex.tv", "roku.com", "amagi.tv", "wurl.tv", "wurl.com")

# Shorteners, file shares and video platforms: one hostname, many unrelated publishers (iptv-org itself lists a
# tinyurl.com stream). Matched as suffixes.
OPEN_HOSTS = (
    "bit.ly", "tinyurl.com", "t.ly", "cutt.ly", "rebrand.ly", "is.gd", "goo.gl", "ow.ly", "tiny.cc", "rb.gy", "s.id",
    "shorturl.at", "t.co", "pastebin.com", "archive.org", "drive.google.com", "docs.google.com", "dropbox.com",
    "dropboxusercontent.com", "onedrive.live.com", "1drv.ms", "mega.nz", "objects.githubusercontent.com",
    "youtube.com", "youtu.be", "dailymotion.com", "twitch.tv", "facebook.com", "vimeo.com", "livestream.com", "ok.ru",
    "vk.com", "rutube.ru", "rumble.com", "odysee.com", "odysee.live", "kick.com", "streamable.com",
)
# Code and path-style storage hosts: the tenant is the owner (or bucket, or video), this many path segments deep.
OWNER_PATH = {
    "raw.githubusercontent.com": 1, "github.com": 1, "gist.githubusercontent.com": 1, "gist.github.com": 1,
    "gitlab.com": 1, "bitbucket.org": 1, "codeberg.org": 1, "raw.githack.com": 1, "rawcdn.githack.com": 1,
    "cdn.jsdelivr.net": 2, "cdn.statically.io": 2, "storage.googleapis.com": 1, "videodelivery.net": 1,
}
S3_PATH_STYLE = re.compile(r"s3(?:[.-][a-z0-9-]+)*\.amazonaws\.com")  # s3.amazonaws.com/<bucket>, s3-<region>...
PROXY_LABEL = re.compile(r"(?:^|[.-])(?:[a-z0-9]*proxy[a-z0-9]*|cors)(?=[.-]|$)")
# Another URL after the authority: a scheme, a protocol-relative value, or base64 of "http" at any alignment
# (aHR0c, h0dHA/h0dHB, odHRw). Searched in the URL and its percent-decoded layers.
EMBEDDED_URL = re.compile(
    r"^[a-z][a-z0-9+.-]*://[^/?#]*[/?#].*?(?:(?:https?|rtmp|ftp)(?::|%3a)|=//[a-z0-9-]+(?:\.[a-z0-9-]+)+|"
    r"ahr0c|h0dh[ab]|odhrw)",
    re.IGNORECASE,
)
URL_DECODE_LAYERS = 3
# Three path segments ending in a number: Xtream's short form (no generic deny pattern: official CDNs share the
# shape, e.g. /hls/KBS/03.m3u8, so those lose host-level admission only).
SHORT_PANEL_PATH = re.compile(r"/[^/?#]+/[^/?#]+/\d+(?:\.\w+)?")
HOST_SHAPE = re.compile(r"[a-z0-9.-]+|[0-9a-f:.]+")  # an ASCII name, an IPv4 address or an IPv6 literal
DEFAULT_PORTS = {"http": 80, "https": 443}


def split_url(url: str) -> tuple[str, str, list[str]] | None:
    """(host, host[:port] without a default port, lowercased path segments), or None when the URL has no host or
    another parser could read its host or path differently."""
    try:
        parts = urlsplit(url.strip())
        host = (parts.hostname or "").lower().rstrip(".")
        port = parts.port
    except ValueError:  # a malformed port or IPv6 literal
        return None
    if not HOST_SHAPE.fullmatch(host):
        return None
    decoded = unquote(parts.path)
    if "\\" in decoded or decoded.count("/") != parts.path.count("/") or {".", ".."} & set(decoded.split("/")):
        return None
    return host, _netloc(host, None if port == DEFAULT_PORTS.get(parts.scheme.lower()) else port), \
        [s.lower() for s in parts.path.split("/") if s]


def _netloc(host: str, port: int | str | None) -> str:
    """host[:port], an IPv6 literal bracketed so [2001:db8::1]:8000 and [2001:db8::1:8000] stay apart."""
    bracketed = f"[{host}]" if ":" in host else host
    return f"{bracketed}:{port}" if port else bracketed


def _owner_depth(host: str) -> int:
    return OWNER_PATH.get(host, 1 if S3_PATH_STYLE.fullmatch(host) else 0)


def _embeds_url(url: str) -> bool:
    layer = url
    for _ in range(URL_DECODE_LAYERS + 1):
        if EMBEDDED_URL.search(layer):
            return True
        decoded = unquote(layer)
        if decoded == layer:
            return False
        layer = decoded
    return False


def has_suffix(host: str, suffixes: tuple[str, ...]) -> bool:
    """Whether the host is one of the suffixes or a subdomain of one."""
    return any(host == s or host.endswith("." + s) for s in suffixes)


def tenant(url: str) -> str | None:
    """The key the host criteria compare (module docstring); None when no host-level admission is allowed."""
    split = split_url(url)
    if split is None:
        return None
    host, netloc, segments = split
    if has_suffix(host, OPEN_HOSTS) or PROXY_LABEL.search(host) or _embeds_url(url):
        return None
    if SHORT_PANEL_PATH.fullmatch(urlsplit(url.strip()).path):
        return None
    depth = _owner_depth(host)
    if len(segments) < depth:
        return None
    return "/".join([netloc] + segments[:depth])


def parse_reviewed(text: str) -> list[tuple[str, list[str]]]:
    """Entries of reviewed-hosts.txt as (host[:port], path-prefix segments). A shared host needs a path prefix; a
    default port is refused because admit() compares netlocs without it."""
    entries = []
    for number, line in enumerate(text.splitlines(), 1):
        entry = line.split("#", 1)[0].strip().lower()
        if not entry:
            continue
        netloc, _, path = entry.partition("/")
        segments = [s for s in path.split("/") if s]
        literal = re.fullmatch(r"\[([0-9a-f:.]+)\](?::(\d+))?", netloc)
        host, _, port = (literal.group(1), "", literal.group(2) or "") if literal else netloc.partition(":")
        if ("://" in entry or " " in entry or "\t" in entry or not HOST_SHAPE.fullmatch(host)
                or not re.fullmatch(r"\d*", port) or port in ("80", "443")):
            raise ValueError(f"reviewed-hosts line {number}: write host[:port][/path] without a default port, "
                             f"got {entry!r}")
        needed = max(_owner_depth(host), 1 if has_suffix(host, OPEN_HOSTS) else 0)
        if len(segments) < needed:
            raise ValueError(f"reviewed-hosts line {number}: {host} is shared; add the owner path")
        entries.append((_netloc(host, port), segments))
    return entries


def stream_urls(streams: object) -> list[str]:
    """Every stream URL in parsed streams.json data."""
    if not isinstance(streams, list):
        raise ValueError("streams.json: expected a JSON array")
    return [s["url"] for s in streams if isinstance(s, dict) and isinstance(s.get("url"), str)]


def iptv_org_urls(path: Path | None = None) -> list[str]:
    """Every stream URL in iptv-org's streams.json, from a local copy or downloaded."""
    if path is not None:
        data = path.read_bytes()
    else:
        with urllib.request.urlopen(IPTV_ORG_STREAMS, timeout=60) as response:
            data = response.read(MAX_DOWNLOAD + 1)
        if len(data) > MAX_DOWNLOAD:
            raise ValueError(f"{IPTV_ORG_STREAMS} is over {MAX_DOWNLOAD} bytes")
    return stream_urls(json.loads(data))


class Allowlist:
    def __init__(self, iptv_org: list[str], reviewed: list[tuple[str, list[str]]], vouches: Callable[[str], bool]):
        """vouches(url) says whether an iptv-org URL may vouch for its host (rules.vouches)."""
        self.urls = frozenset(iptv_org)
        self.tenants = frozenset(t for t in map(tenant, filter(vouches, self.urls)) if t is not None)
        self.reviewed = reviewed

    @classmethod
    def load(cls, streams_json: Path | None, vouches: Callable[[str], bool]) -> "Allowlist":
        return cls(iptv_org_urls(streams_json), parse_reviewed(REVIEWED_HOSTS.read_text(encoding="utf-8")), vouches)

    def admit(self, url: str) -> str | None:
        """The criterion that makes the URL public, or None."""
        if url in self.urls:
            return "iptv-org-url"
        split = split_url(url)
        if split is None:
            return None
        host, netloc, segments = split
        key = tenant(url)
        if key is not None and has_suffix(host, FAST_SUFFIXES):
            return "fast-host"
        if key is not None and key in self.tenants:
            return "iptv-org-host"
        if any(netloc == n and segments[:len(prefix)] == prefix for n, prefix in self.reviewed):
            return "reviewed-host"
        return None
