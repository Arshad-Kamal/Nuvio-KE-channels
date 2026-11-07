"""Fetching and parsing the list endpoints the pool is built from (Nuvio-Project Spec 60 H1b).

Every function returns candidate rows in extract_research.COLUMNS shape (plus "tvg_id"); bucketing happens in
build_pool.py. Remote content is untrusted: cells are single-line and length-capped, a URL holding whitespace or
over MAX_URL is skipped, fetches only reach public addresses over http(s), and each response is capped in size and
time. The headers cell is a compact ASCII JSON object of Referer / User-Agent / Origin (a User-Agent holds "; ", so
a delimited list could not be split back), or "-".
"""
import gzip
import http.client
import io
import ipaddress
import json
import re
import socket
import time
import urllib.request
import zlib
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from urllib.parse import quote, unquote, urlsplit, urlunsplit

from allowlist import IPTV_ORG_API, IPTV_ORG_STREAMS, MAX_DOWNLOAD, has_suffix
from rules import (DRM, LIST_KINDS, M3U_FILE, NSFW_NAME, STATIC_SOURCES, Verdict, hidden_credential, nsfw_category,
                   stricter, token_shaped)

MAX_GUNZIPPED = MAX_DOWNLOAD  # real lists are far smaller; 8 parallel fetches stay within a few hundred MB
FETCH_TIMEOUT = 30  # per socket operation
FETCH_DEADLINE = 120  # whole response
USER_AGENT = "Nuvio-KE-channels harvest (+https://github.com/Arshad-Kamal/Nuvio-KE-channels)"
MAX_NAME = 200
MAX_URL = 4096

# FAST indexes: one row per channel id, its URL in the jmp2.uk form iptv-org (or, for Plex, the lists) already use.
# Samsung's index names its own slug ("stvp-{id}"); the others are fixed here.
FAST_INDEXES = {
    "pluto": ("https://i.mjh.nz/PlutoTV/.channels.json", "https://jmp2.uk/plu-{id}.m3u8"),
    "samsung": ("https://i.mjh.nz/SamsungTVPlus/.channels.json", "https://jmp2.uk/{slug}"),
    "roku": ("https://i.mjh.nz/Roku/.channels.json", "https://jmp2.uk/rok-{id}.m3u8"),
    "plex": ("https://i.mjh.nz/Plex/.channels.json", "https://jmp2.uk/plex-{id}.m3u8"),
}
FAST_ID = re.compile(r"[A-Za-z0-9-]{1,64}")  # an index id goes into a URL path: no "/", "?", "." or "%"
FAST_SLUG = re.compile(r"[A-Za-z0-9-]*\{id\}[A-Za-z0-9.-]*")  # one id per URL, nothing a parser reads as structure

URL_START = re.compile(r"[a-z][a-z0-9+.-]*://", re.IGNORECASE)
# A URL inside free text (an #EXTINF logo): a scheme starts only where a scheme run starts, so linear.
URL_IN_TEXT = re.compile(r"(?<![a-z0-9+.-])[a-z][a-z0-9+.-]*+://[^\s\"',]*+", re.IGNORECASE)
# Not streams: images, and web pages without a query (a JSON list's player-page links; Rai's relinkerServlet.htm?cont=
# is a stream redirector).
NOT_STREAM = re.compile(r"\.(?:png|jpe?g|gif|svg|webp|ico|bmp)(?:[?#]|$)|\.html?$", re.IGNORECASE)
HLS_MEDIA_PLAYLIST = re.compile(r"^#EXT-X-(?:TARGETDURATION|MEDIA-SEQUENCE)", re.MULTILINE)
JSON_URL_KEY = re.compile(r"url|link|stream|src|file|source|m3u|hls|play", re.IGNORECASE)
JSON_NOT_STREAM_KEY = re.compile(r"logo|image|icon|thumb|poster|banner|fanart|^art|epg|guide|site|home|page|license",
                                 re.IGNORECASE)
JSON_NAME_KEYS = ("name", "title", "channel", "channel_name", "nombre", "nome")
JSON_CATEGORY_KEYS = ("category", "categories", "group", "group_title", "group-title", "genre", "genres")
# The request headers kept, by the names lists use (EXTVLCOPT http-* options, Kodi "|Name=value" suffixes). Others
# (Cookie, Authorization...) are dropped: they would publish a session.
HEADER_NAMES = {"http-referrer": "Referer", "http-user-agent": "User-Agent", "http-origin": "Origin",
                "referer": "Referer", "referrer": "Referer", "user-agent": "User-Agent", "origin": "Origin"}
MAX_HEADER = 1000

# Research list endpoints that are list files (Spec 60 H1b plan). iptv-org's own playlists hold nothing streams.json
# lacks (measured 2026-11-07: 15,552 URLs, 0 outside it); the i.mjh.nz indexes are read as FAST_INDEXES; API
# directory listings and EPG files are not stream lists; JSON from a non-static host is a broadcaster API, which
# mints URLs for the requester (Spec 60 A0 recipes resolve those on the viewer's device).
GITHUB_FILE = re.compile(r"https://github\.com/([^/?#]+)/([^/?#]+)/(?:blob|raw)/([^?#]+)", re.IGNORECASE)
GIST_PAGE = re.compile(r"https://gist\.github\.com/([^/?#]+)/([0-9a-f]+)/?(?:[?#]|$)", re.IGNORECASE)
IPTV_ORG_OWN = re.compile(r"https?://(?:iptv-org\.github\.io/|(?:raw\.githubusercontent|github)\.com/iptv-org/)",
                          re.IGNORECASE)
EPG_PATH = re.compile(r"epg|guide|\.xml(?:\.gz)?$", re.IGNORECASE)  # not on an M3U path (OpenIPTVItaly_No_EPG.m3u)
PAGE_HOSTS = ("github.com", "api.github.com", "gist.github.com")
REDIRECTORS = ("jmp2.uk", "c.mjh.nz")  # and i.mjh.nz/.r/: one stream each, answered per requester


class FetchError(Exception):
    pass


@dataclass
class Fetched:
    url: str  # as requested
    final_url: str  # after redirects
    body: bytes


SURROGATE = re.compile("[\ud800-\udfff]")  # JSON "\ud800" escapes decode to lone surrogates: not encodable as UTF-8


def cell(value: object, limit: int = MAX_NAME) -> str:
    """One TSV cell from untrusted text: whitespace runs (tabs, newlines) collapsed, lone surrogates replaced, capped,
    "-" when empty."""
    text = " ".join(SURROGATE.sub("\ufffd", str(value)).split())[:limit]
    return text or "-"


def clean_url(text: object) -> str | None:
    """The URL when it is one whitespace- and surrogate-free token with a scheme, at most MAX_URL characters, that
    urlsplit can read (an unbalanced "[" raises there), else None."""
    if (not isinstance(text, str) or len(text) > MAX_URL or text.split() != [text] or not URL_START.match(text)
            or SURROGATE.search(text)):
        return None
    try:
        urlsplit(text).port
    except ValueError:
        return None
    return text


def headers_cell(pairs: list[tuple[str, str]]) -> str:
    """The headers cell (module docstring) from (name, value) pairs; unknown names are dropped, the first value of a
    name wins."""
    found: dict[str, str] = {}
    for name, value in pairs:
        canonical = HEADER_NAMES.get(name.strip().lower())
        if canonical:
            value = " ".join(value.split())[:MAX_HEADER]
            if value:
                found.setdefault(canonical, value)
    return json.dumps(found, separators=(",", ":")) if found else "-"


def row(name: str, url: str, source: str, **cells: str) -> dict[str, str]:
    """A candidate row; every cell but headers (built by headers_cell) is cleaned with cell()."""
    values = dict(name=cell(name), url=url, country="-", language="-", category="-", kind="stream", format="-",
                  headers="-", geo_hint="-", source_page=source, notes="-", tvg_id="")
    for key, value in cells.items():
        values[key] = value if key == "headers" else cell(value, 100 if key == "tvg_id" else MAX_NAME)
    if values["tvg_id"] == "-":
        values["tvg_id"] = ""
    return values


def list_url(url: str) -> str:
    """One spelling per list file, the one fetched: a GitHub blob/raw page as raw.githubusercontent.com, a gist page
    as its /raw, refs/heads/<ref> as <ref> (raw.githubusercontent.com serves both alike)."""
    url = url.strip()
    if file := GITHUB_FILE.match(url):
        url = "https://raw.githubusercontent.com/{}/{}/{}".format(*file.groups())
    elif gist := GIST_PAGE.match(url):
        url = "https://gist.github.com/{}/{}/raw".format(*gist.groups())
    return re.sub(r"^(https://raw\.githubusercontent\.com/[^/]+/[^/]+/)refs/heads/", r"\1", url, flags=re.IGNORECASE)


def list_taint(research: Mapping[str, str]) -> Verdict | None:
    """The verdict every row of a research list carries (its merged "_bucket" and "reason"): nsfw for a list the
    research put in nsfw, private (this copy only) for a listed pirate list; None otherwise."""
    if research["_bucket"] == "nsfw":
        return Verdict("nsfw", "nsfw")
    if research["reason"].startswith("listed:"):
        return Verdict("private", research["reason"], copy_only=True)
    return None


def list_taints(research_lists: Iterable[Mapping[str, str]]) -> dict[str, Verdict | None]:
    """list_url -> the strictest list_taint of every research list row naming that file. Rows pulled from the file
    and research stream rows citing it (cited_taint) carry it."""
    taints: dict[str, Verdict | None] = {}
    for research in research_lists:
        key = list_url(research["url"])
        taints[key] = stricter(taints.get(key), list_taint(research))
    return taints


def cited_taint(taints: Mapping[str, Verdict | None], row: Mapping[str, str]) -> Verdict | None:
    """The taint a research stream row carries from the research list its source page names (None for list rows)."""
    return None if row["kind"] in LIST_KINDS else taints.get(list_url(row["source_page"]))


def list_target(row: Mapping[str, str]) -> tuple[str | None, str]:
    """(URL to fetch, class) for one research list-endpoint/api row; the URL (list_url's spelling) is None when it is
    not pulled and the class says why."""
    url = list_url(row["url"])
    if not re.match(r"https?://", url, re.IGNORECASE):
        return None, "skip:not-http"
    if "{" in url:
        return None, "skip:template"
    if IPTV_ORG_OWN.match(url):
        return None, "skip:iptv-org"
    try:
        parts = urlsplit(url)
        host, path = (parts.hostname or "").lower(), unquote(parts.path)
    except ValueError:
        return None, "skip:not-http"
    if "xmltv" in row["format"].lower() or (EPG_PATH.search(path) and not M3U_FILE.search(path)):
        return None, "skip:epg"
    if host == "i.mjh.nz" and ".channels.json" in path:
        return None, "skip:fast-index"
    if host in PAGE_HOSTS and not path.endswith("/raw"):
        return None, "skip:page"
    if path.startswith("/.r/") or has_suffix(host, REDIRECTORS):
        return None, "skip:redirector"
    # Fetching a URL that carries someone's login or session would use it (Spec 60 D16, D17), NSFW-named or not.
    if hidden_credential(url):
        return None, "skip:credential"
    if token_shaped(url):
        return None, "skip:token"
    if has_suffix(host, STATIC_SOURCES):
        return url, "static"
    if M3U_FILE.search(path) or row["format"].lower().startswith("m3u"):
        return url, "other-host"
    return None, "skip:api"


# --- fetching ---------------------------------------------------------------------------------------------------

def _public_host(url: str) -> None:
    """Refuses a URL that is not http(s) or whose host resolves to any non-public address (the LAN, loopback)."""
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as error:
        raise FetchError(f"bad URL: {error}") from error
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        raise FetchError(f"not an http(s) URL: {url[:200]}")
    try:
        infos = socket.getaddrinfo(parts.hostname, port or 443, proto=socket.IPPROTO_TCP)
    except (OSError, UnicodeError) as error:
        raise FetchError(f"cannot resolve {parts.hostname}: {error}") from error
    for info in infos:
        address = ipaddress.ip_address(info[4][0].split("%")[0])
        if not address.is_global:
            raise FetchError(f"{parts.hostname} resolves to a non-public address")


class _PublicRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _public_host(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_PublicRedirects)


def _encoded(url: str) -> str:
    """The URL with spaces and non-ASCII in its path and query percent-encoded (research recorded some as read)."""
    parts = urlsplit(url)
    return urlunsplit(parts._replace(path=quote(parts.path, safe="/%:@!$&'()*+,;=~"),
                                     query=quote(parts.query, safe="/%:@!$&'()*+,;=~?")))


def fetch(url: str) -> Fetched:
    """GETs one URL within the size and time caps; a gzip body is decompressed."""
    _public_host(url)
    try:
        request = urllib.request.Request(_encoded(url),
                                         headers={"User-Agent": USER_AGENT, "Accept-Encoding": "identity"})
    except ValueError as error:
        raise FetchError(f"bad URL: {error}") from error
    deadline = time.monotonic() + FETCH_DEADLINE
    chunks, size = [], 0
    try:
        with _OPENER.open(request, timeout=FETCH_TIMEOUT) as response:
            final_url = response.geturl()
            while chunk := response.read1(1 << 16):  # one socket read per call, so the deadline is checked
                size += len(chunk)
                if size > MAX_DOWNLOAD:
                    raise FetchError(f"over {MAX_DOWNLOAD} bytes")
                if time.monotonic() > deadline:
                    raise FetchError(f"over {FETCH_DEADLINE} s")
                chunks.append(chunk)
    except (OSError, ValueError, http.client.HTTPException) as error:  # URLError/HTTPError/timeouts are OSErrors
        raise FetchError(str(error)[:200]) from error
    body = b"".join(chunks)
    if body[:2] == b"\x1f\x8b":
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(body)) as unzipped:
                body = unzipped.read(MAX_GUNZIPPED + 1)
        except (OSError, EOFError, zlib.error) as error:
            raise FetchError(f"bad gzip: {error}") from error
        if len(body) > MAX_GUNZIPPED:
            raise FetchError(f"over {MAX_GUNZIPPED} bytes gunzipped")
    return Fetched(url, final_url, body)


# --- parsing ----------------------------------------------------------------------------------------------------

# Quoted attributes (some lists write tvg-logo= "..."). A key starts after a non-key character, so a long run of
# key characters is tried once, not from each of its positions (linear time on a hostile line).
EXTINF_ATTRIBUTE = re.compile(r'(?<![\w-])([\w-]+)\s*=\s*"([^"]*)"')
# Unquoted or half-quoted attributes before the name (tvg-chno=69, tvg-id=Action 24.gr"): split on their keys.
BARE_KEY = re.compile(r"(?<![\w-])((?:tvg|group)-[\w-]+)\s*=", re.IGNORECASE)
# A leading-comma list's run of unquoted attributes between commas before the name; possessive, so linear.
BARE_RUN = re.compile(r"(?:[ \t,]*+(?:tvg|group)-[\w-]++\s*+=[^,]*+)++", re.IGNORECASE)
DURATION = re.compile(r"^\s*-?\d+(?:\.\d+)?")


def _extinf(line: str) -> tuple[dict[str, str], str, str]:
    """(attributes, name, leftover) of an #EXTINF line. Quoted attributes are read wherever they stand (some lists
    write '#EXTINF:-1,tvg-id="X",tvg-logo="...",Name') and removed; the name follows the first comma left, leading
    commas dropped, so a name holding a comma ("CNN, East") stays whole. Before the name stand the duration and
    unquoted attributes, each value running to the next key, stray quotes and separating commas stripped; leading-comma
    lists put them after the duration's comma, and a line with no comma left is read the same way when it starts with
    one. Leftover = the rest of that part (a mispaired quote's spill, an unknown key), for the NSFW rules (parse_m3u)."""
    attributes = {k.lower(): v for k, v in EXTINF_ATTRIBUTE.findall(line)}
    rest = DURATION.sub("", EXTINF_ATTRIBUTE.sub("", line[len("#EXTINF:"):]))
    head, comma, name = rest.partition(",")
    if not comma:
        if not BARE_KEY.match(rest.strip()):
            return attributes, rest.strip(), ""
        head, name = rest, ""
    name = name.lstrip(" \t,")
    if run := BARE_RUN.match(name):
        head, name = f"{head} {run.group()}", name[run.end():].lstrip(" \t,")
    parts = BARE_KEY.split(head)  # [leftover, key, value, key, value, ...]
    for key, value in zip(parts[1::2], parts[2::2]):
        attributes.setdefault(key.lower(), value.strip(' \t,"'))
    return attributes, name.strip(), parts[0].strip(' \t,"')


def _stream_url(token: str) -> tuple[str, list[tuple[str, str]], bool] | None:
    """The URL of one list entry, the (name, value) pairs of a Kodi-style "|Name=value&..." suffix, and whether a pair
    names DRM (a DRM or license name such as NS Player's drmScheme/drmLicense, or a DRM value such as clearkey); None
    for an unclean URL, an image or a web page."""
    url, _, kodi = token.partition("|")
    if clean_url(url) is None or NOT_STREAM.search(url):
        return None
    pairs = [(name, unquote(value)) for name, _, value in (pair.partition("=") for pair in kodi.split("&") if pair)]
    return url, pairs, any(_drm_key(name) or DRM.search(value) for name, value in pairs)


def _drm_key(key: object) -> bool:
    """Whether a key names DRM or a license (a JSON key, a Kodi suffix pair name): a DRM term, a name starting with
    "drm" (drmScheme), or "license"."""
    lowered = str(key).lower()
    return bool(DRM.search(lowered)) or lowered.startswith("drm") or "license" in lowered


def _category(parts: Iterable[str | None], nsfw: bool = False) -> str:
    """A category cell: the distinct parts, nearest first, joined and capped. When the parts or the entry's other text
    (nsfw) name adult content and the capped cell no longer shows it, the cell starts with "nsfw", so the rules still
    see it (a long ancestor list or group-title had cut a child's "XXX")."""
    text = "; ".join(dict.fromkeys(p.strip() for p in parts if p and p.strip() and p.strip() != "-"))
    if (nsfw or nsfw_category(text)) and not nsfw_category(cell(text)):
        text = f"nsfw; {text}" if text else "nsfw"
    return cell(text)


def parse_m3u(text: str, source: str) -> Iterator[dict[str, str]]:
    """Rows of an extended M3U playlist (#EXTINF + URL line). Directives may come before or after #EXTINF (Kodi lists
    put #KODIPROP first), so an entry's state is cleared only after its URL line. The category is group-title and
    #EXTGRP. NSFW signals beyond the name and category cells: the name terms (NSFW_NAME) anywhere in the #EXTINF line
    but its URLs (tvg-name, a name an unquoted attribute swallowed; a logo URL's random "7IxXX6f" is not a name), and
    the category rules on the leftover (_extinf). A URL line with no #EXTINF of its own (another URL of the entry
    before) is unnamed but keeps that entry's NSFW signal."""
    extinf, headers, drm, group, nsfw = "", [], False, "", False
    for raw in text.splitlines():
        line = raw.strip().lstrip("\ufeff")
        if line.startswith("#EXTINF"):
            extinf = line
        elif line.startswith("#EXTVLCOPT:"):
            option, _, value = line[len("#EXTVLCOPT:"):].partition("=")
            headers.append((option, value))
        elif line.startswith("#KODIPROP:"):
            drm = drm or "license" in line.lower() or "drm" in line.lower()
        elif line.startswith("#EXTGRP:"):
            group = line[len("#EXTGRP:"):]
        elif line and not line.startswith("#"):
            attributes, name, leftover = _extinf(extinf) if extinf else ({}, "", "")
            categories = (attributes.get("group-title"), group)
            nsfw = ((nsfw and not extinf) or bool(NSFW_NAME.search(URL_IN_TEXT.sub(" ", extinf)))
                    or nsfw_category(leftover) or nsfw_category("; ".join(filter(None, categories))))
            found = _stream_url(line.split()[0])
            if found:
                url, kodi_headers, kodi_drm = found
                yield row(name or attributes.get("tvg-name", ""), url, source,
                          country=attributes.get("tvg-country", "-"), language=attributes.get("tvg-language", "-"),
                          category=_category(categories, nsfw),
                          headers=headers_cell(headers + kodi_headers),
                          notes="KODIPROP license (DRM)" if drm else "license pair (DRM)" if kodi_drm else "-",
                          tvg_id=attributes.get("tvg-id", ""))
            extinf, headers, drm, group = "", [], False, ""


def _json_category(node: dict) -> str | None:
    """The node's own category: the first category/group/genre key holding a string or a list of strings."""
    for key in JSON_CATEGORY_KEYS:
        value = node.get(key)
        if isinstance(value, list):
            value = "; ".join(v for v in value if isinstance(v, str))
        if isinstance(value, str) and value.strip():
            return value
    return None


def parse_json_list(data: object, source: str) -> Iterator[dict[str, str]]:
    """Rows of a JSON list of any shape: string URLs under stream-like keys, named by the nearest name key; the category
    is the node's own, then its ancestors' (a group's "XXX" survives a child's "Movies" and reaches the NSFW rules),
    capped (_category). A node with a license/DRM key, or a Kodi DRM pair on the URL, marks its own URLs DRM, not its
    children's (a root "license" is the list's content licence; a clearkey channel's "fallback" is its non-DRM
    variant); a site root is not a stream."""
    stack = [(data, ("", "-"))]
    while stack:
        node, context = stack.pop()
        if isinstance(node, list):
            stack.extend((child, context) for child in reversed(node))
            continue
        if not isinstance(node, dict):
            continue
        name = next((node[k] for k in JSON_NAME_KEYS if isinstance(node.get(k), str)), context[0])
        category = _category((_json_category(node), context[1]))
        drm = any(_drm_key(key) for key in node)
        children = []
        for key, value in node.items():
            if isinstance(value, str):
                found = _stream_url(value.strip()) if value.strip().split() == [value.strip()] else None
                # clean_url already proved urlsplit reads the URL
                if (found and JSON_URL_KEY.search(key) and not JSON_NOT_STREAM_KEY.search(key)
                        and urlsplit(found[0]).path.strip("/")):
                    yield row(name, found[0], source, category=category, headers=headers_cell(found[1]),
                              notes="license key (DRM)" if drm or found[2] else "-")
            elif isinstance(value, (dict, list)):
                children.append((value, (name, category)))
        stack.extend(reversed(children))


def parse_list(fetched: Fetched, m3u_only: bool = False) -> tuple[str, list[dict[str, str]]]:
    """(kind, rows) of a fetched body: kind "m3u", "json", or "not-a-list" (HLS playlists, pages, other JSON). An HLS
    media playlist has #EXTINF per segment, so it is told apart by its media tags. m3u_only: JSON is not parsed (a
    non-static host's JSON is an API answer, never a list)."""
    text = fetched.body.decode("utf-8", "replace")
    if "#EXTINF" in text and not HLS_MEDIA_PLAYLIST.search(text):
        return "m3u", list(parse_m3u(text, fetched.final_url))
    if not m3u_only and text.lstrip("\ufeff \t\r\n")[:1] in ("[", "{"):
        try:
            data = json.loads(text.lstrip("\ufeff"))
        except (ValueError, RecursionError):
            return "not-a-list", []
        rows = list(parse_json_list(data, fetched.final_url))
        return ("json", rows) if rows else ("not-a-list", [])
    return "not-a-list", []


def _iptv_org_headers(stream: dict) -> str:
    """iptv-org's referrer/user_agent as a headers cell; a UA may carry an "#EXTVLCOPT:http-user-agent=" prefix."""
    pairs = [("Referer", stream.get("referrer")), ("User-Agent", stream.get("user_agent"))]
    return headers_cell([(name, re.sub(r"^#EXTVLCOPT:http-user-agent=", "", value, flags=re.IGNORECASE))
                         for name, value in pairs if isinstance(value, str) and value.strip()])


def iptv_org_rows(streams: list) -> Iterator[dict[str, str]]:
    """Rows of iptv-org's streams.json; tvg_id = channel[@feed] as iptv-org's playlists write it. A URL that is not
    one clean token is skipped (allowlist.Allowlist still matches iptv-org's strings exactly)."""
    for stream in streams:
        if not isinstance(stream, dict) or clean_url(stream.get("url")) is None:
            continue
        labels = [str(label) for label in stream["labels"]] if isinstance(stream.get("labels"), list) else []
        channel = stream.get("channel") or ""
        feed = stream.get("feed") or ""
        notes = labels + ([f"quality {stream['quality']}"] if stream.get("quality") else [])
        yield row(stream.get("title") or channel, stream["url"], IPTV_ORG_STREAMS, headers=_iptv_org_headers(stream),
                  geo_hint="geo-blocked" if "Geo-blocked" in labels else "-", notes="; ".join(notes) or "-",
                  tvg_id=f"{channel}@{feed}" if channel and feed else channel)


def _fast_channels(service: str, index: dict) -> Iterator[tuple[str, dict, list[str]]]:
    """(id, channel, region codes) of one i.mjh.nz index; a channel listed in several regions is yielded once."""
    if service in ("pluto", "samsung"):
        seen: dict[str, tuple[dict, list[str]]] = {}
        for code, region in index["regions"].items():
            for channel_id, channel in region["channels"].items():
                seen.setdefault(channel_id, (channel, []))[1].append(code)
        for channel_id, (channel, regions) in seen.items():
            yield channel_id, channel, regions
    elif service == "plex":
        for channel_id, channel in index["channels"].items():
            yield channel_id, channel, list(channel.get("regions") or [])
    else:  # The Roku Channel's index has no regions: it is a US service
        for channel_id, channel in index["channels"].items():
            yield channel_id, channel, ["us"]


def fast_rows(service: str, index: dict) -> Iterator[dict[str, str]]:
    """Rows of one FAST index (FAST_INDEXES); raises ValueError when its shape changed."""
    source, template = FAST_INDEXES[service]
    try:
        slug = index.get("slug", "stvp-{id}") if service == "samsung" else "{id}"
        if not isinstance(slug, str) or not FAST_SLUG.fullmatch(slug):
            raise ValueError(f"slug {slug!r}")
        for channel_id, channel, regions in _fast_channels(service, index):
            if not isinstance(channel_id, str) or not FAST_ID.fullmatch(channel_id):
                continue
            url = template.format(id=channel_id, slug=slug.replace("{id}", channel_id))
            group = channel.get("group") or ";".join(channel.get("groups") or []) or "-"
            yield row(channel.get("name", ""), url, source, country=";".join(r.upper() for r in regions) or "-",
                      category=group, notes="license_url (DRM)" if channel.get("license_url") else "-")
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError(f"{source}: unexpected shape ({error!r})") from error
