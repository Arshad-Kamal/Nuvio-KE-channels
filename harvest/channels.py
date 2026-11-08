"""Channel key and iptv-org joins for pool rows (Nuvio-Project Spec 60 H1b).

Rows stay one per exact URL; the channel column groups alternates of one channel, keyed in the Spec 60 W3 dedupe order
after the exact URL: the iptv-org channel[@feed] of the exact URL; the iptv-org channel of the same host+path (any
query) when only one channel uses it and none of iptv-org's URLs on it carries a query (a query can name the channel:
one ssai.aniview.com path serves every channel by ?AVS_SSAIID=, and keyed 348 others to FashionTV Secrets; Spec 71
M1.1); a FAST provider id (mapped to the iptv-org channel that uses the same id when only
one does, else "<service>:<id>"); a tvg-id naming a channels.json id; a name + 2-letter country naming exactly one
channels.json channel; else empty. A row whose channel key or tvg-id names a channel iptv-org blocklists or marks NSFW
(Channels._nsfw) moves bucket, as does one the owner rules NSFW (NSFW_CHANNELS: by the channel's own key or a tvg-id,
never a host+path neighbour's key); so does a row whose key names no channels.json channel (empty, "<service>:<id>") and
whose name (any copy's) is an NSFW channel's name or alt name in any country (Spec 60 D19 audit: iptv-org lists no
stream for Pluto DE's erotic channels, so their provider ids map to nothing). spread_nsfw then moves every URL holding a
FAST channel id an nsfw row's URL holds (Spec 60 D20). Every value taken from iptv-org's files is cleaned with
lists.cell before it is published.
"""
import re
import unicodedata
from collections import defaultdict
from collections.abc import Iterable
from urllib.parse import unquote, urlsplit

import egress
from lists import cell
from rules import nsfw_category

JMP2_SLUGS = {"plu": "pluto", "stvp": "samsung", "sam": "samsung", "rok": "roku", "plex": "plex"}
JMP2_PATH = re.compile(r"/(plu|stvp|sam|rok|plex)-([A-Za-z0-9-]+?)(?:\.m3u8)?")
PLUTO_PATH = re.compile(r"/channels?/([0-9a-f]{24})(?:/|$)", re.IGNORECASE)
# The per-service redirector spelling on i.mjh.nz and jmp2.uk (/PlutoTV/<id>-alt.m3u8, /SamsungTVPlus/<id>.m3u8)
SERVICE_PATH = re.compile(r"/(PlutoTV|SamsungTVPlus|Roku|Plex)/([A-Za-z0-9-]+?)(?:-alt)?\.m3u8", re.IGNORECASE)
SERVICE_DIRS = {"plutotv": "pluto", "samsungtvplus": "samsung", "roku": "roku", "plex": "plex"}
# A FAST channel id as the indexes write it, lowercased (a Plex key "<lineup>-<channel>": its channel part). Nothing
# shorter or looser can reach other rows (spread_nsfw).
FAST_ID_SHAPES = {"pluto": re.compile(r"[0-9a-f]{24}"), "samsung": re.compile(r"[a-z]{2,4}\d{6,}[a-z0-9]{0,3}"),
                  "roku": re.compile(r"[0-9a-f]{32}"), "plex": re.compile(r"[0-9a-f]{24}")}
URL_WORD = re.compile(rb"[0-9a-z]+")
# channels.json ids iptv-org files SFW that the owner rules NSFW (Spec 60 D21: a list files FashionTV Secrets "Erotic")
NSFW_CHANNELS = {"fashiontvsecrets.fr"}
QUALITY = re.compile(r"\b(?:u?hd|fhd|sd|[48]k|hevc|h\.?26[45]|\d{3,4}[pi]|backup|geo-blocked|not 24/7)\b")
COUNTRY_CODE = re.compile(r"[A-Za-z]{2}")


def _split(url: str) -> tuple[str, str] | None:
    """(host[:port], decoded path), or None for a malformed URL."""
    try:
        parts = urlsplit(url)
        host, port = (parts.hostname or "").lower(), parts.port
    except ValueError:
        return None
    return (f"{host}:{port}" if port else host), unquote(parts.path)


def provider_id(url: str) -> str | None:
    """"<service>:<id>" for a FAST URL (jmp2.uk slugs, i.mjh.nz/jmp2.uk per-service paths, Pluto stitcher paths,
    i.mjh.nz .r slugs), else None."""
    split = _split(url)
    if split is None:
        return None
    host, path = split
    if host == "jmp2.uk" and (slug := JMP2_PATH.fullmatch(path)):
        return f"{JMP2_SLUGS[slug[1]]}:{slug[2].lower()}"
    if host in ("i.mjh.nz", "jmp2.uk") and (named := SERVICE_PATH.fullmatch(path)):
        service, ident = SERVICE_DIRS[named[1].lower()], named[2].lower()
        if _channel_id(service, ident):  # not a playlist such as /PlutoTV/us.m3u8
            return f"{service}:{ident}"
    if (host == "pluto.tv" or host.endswith(".pluto.tv")) and (channel := PLUTO_PATH.search(path)):
        return f"pluto:{channel[1].lower()}"
    if host == "i.mjh.nz" and path.startswith("/.r/") and len(path) > 4:
        return cell("mjh:" + re.sub(r"\.m3u8$", "", path[4:].lower()), 100)  # the decoded path is untrusted text
    return None


def _host_path(url: str) -> tuple[str, str] | None:
    split = _split(url)
    return split if split and split[0] and len(split[1]) > 1 else None


def name_key(name: str) -> str:
    """A channel name compared without case, width forms, bracketed tags or quality words."""
    text = unicodedata.normalize("NFKC", name).casefold()
    text = re.sub(r"\[[^\]]*\]|\([^)]*\)", " ", text)
    return " ".join(re.findall(r"\w+", QUALITY.sub(" ", text)))


def _name_keys(info: dict) -> Iterable[str]:
    """A channels.json channel's name and alt names, as name keys (empty ones skipped)."""
    for name in [info.get("name")] + list(info.get("alt_names") or []):
        if isinstance(name, str) and (key := name_key(name)):
            yield key


def _owner_nsfw(channel: str) -> bool:
    """Whether the owner rules a channels.json id (or channel@feed) NSFW (NSFW_CHANNELS)."""
    return channel.split("@")[0].lower() in NSFW_CHANNELS


def _to_nsfw(row: dict) -> None:
    if row["_bucket"] != "nsfw":
        row["_bucket"], row["reason"] = "nsfw", "nsfw"


def _channel_id(service: str, ident: str) -> str | None:
    """The channel id in the ident of a provider id when it has its service's shape (FAST_ID_SHAPES; .r slugs are
    names, never ids). A Plex key needs both parts and gives its channel part: the lineup part is shared by every
    channel of the lineup."""
    if service == "plex":
        _, separator, ident = ident.rpartition("-")
        if not separator:
            return None
    shape = FAST_ID_SHAPES.get(service)
    return ident if shape and shape.fullmatch(ident) else None


def fast_id(url: str) -> str | None:
    """The FAST channel id a URL names (provider_id, _channel_id), or None."""
    service, _, ident = (provider_id(url) or "").partition(":")
    return _channel_id(service, ident)


def _url_words(url: str) -> set[str]:
    """The lowercased letter-digit runs of a URL and its percent-decoded layers."""
    return {word.decode() for layer in egress.layers(url) for word in URL_WORD.findall(layer.lower())}


def spread_nsfw(rows: Iterable[dict]) -> tuple[int, int]:
    """Moves to nsfw every row whose URL holds, as a whole word, a FAST channel id an nsfw row's URL holds, however
    either spells the channel (a stitcher path, a per-service path, a proxy's query value, any case): the verdict
    belongs to the channel (Spec 60 D20). An id is a fast_id of some row; a Plex lineup part never is (one row naming a
    lineup would move the whole lineup). Ids only, never a name or channel key: a mislabelled row drags at most the
    FAST channels its URL names. Returns (ids spread, rows moved)."""
    rows = list(rows)
    known, lineups = set(), set()
    for row in rows:
        service, _, ident = (provider_id(row["url"]) or "").partition(":")
        if channel := _channel_id(service, ident):
            known.add(channel)
            if service == "plex":
                lineups.add(ident.rpartition("-")[0])
    known -= lineups
    ids = {word for row in rows if row["_bucket"] == "nsfw" for word in _url_words(row["url"]) & known}
    moved = [row for row in rows if row["_bucket"] != "nsfw" and not ids.isdisjoint(_url_words(row["url"]))]
    for row in moved:
        _to_nsfw(row)
    return len(ids), len(moved)


def _unique(pairs: Iterable[tuple[object, str]]) -> dict:
    """key -> value for the keys that map to exactly one value."""
    found: dict[object, set[str]] = defaultdict(set)
    for key, value in pairs:
        found[key].add(value)
    return {key: values.pop() for key, values in found.items() if len(values) == 1}


class Channels:
    def __init__(self, streams: list, channels: list, blocklist: list):
        """iptv-org's streams.json, channels.json and blocklist.json, parsed."""
        self.info = {c["id"].lower(): c for c in channels if isinstance(c, dict) and isinstance(c.get("id"), str)}
        listed = [(s["url"], cell(s["channel"], 100), s.get("feed")) for s in streams
                  if isinstance(s, dict) and isinstance(s.get("url"), str) and isinstance(s.get("channel"), str)]
        self.by_url = {url: cell(f"{channel}@{feed}", 100) if feed else channel for url, channel, feed in listed}
        paths = [(url, _host_path(url), provider_id(url), channel) for url, channel, _ in listed]
        # path_neighbour: the one iptv-org channel on a host+path; it keys a row only where no iptv-org URL on the path
        # has a query (by_path), but its NSFW/blocklist flags reach every row on the path (apply).
        self.path_neighbour = _unique((path, channel) for _, path, _, channel in paths if path)
        queried = {path for url, path, _, _ in paths if path and urlsplit(url).query}
        self.by_path = {path: channel for path, channel in self.path_neighbour.items() if path not in queried}
        self.by_provider = _unique((provider, channel) for _, _, provider, channel in paths if provider)
        self.by_name = _unique(((info["country"].upper(), name), info["id"]) for info in self.info.values()
                               if isinstance(info.get("country"), str) for name in _name_keys(info))
        self.blocked = {b["channel"].lower(): str(b.get("reason") or "listed") for b in blocklist
                        if isinstance(b, dict) and isinstance(b.get("channel"), str)}
        self.nsfw_names = {name for info in self.info.values() if self._nsfw(info) or _owner_nsfw(info["id"])
                           for name in _name_keys(info)}

    def _nsfw(self, info: dict) -> bool:
        """Whether iptv-org marks the channel NSFW: is_nsfw, an nsfw blocklist reason, or an NSFW category."""
        categories = info.get("categories") if isinstance(info.get("categories"), list) else []
        return (info.get("is_nsfw") is True or self.blocked.get(info["id"].lower()) == "nsfw"
                or nsfw_category(";".join(str(c) for c in categories)))

    def key(self, row: dict, tvg_id: str) -> str:
        """The channel key of one pool row (module docstring)."""
        url = row["url"]
        if url in self.by_url:
            return self.by_url[url]
        path = _host_path(url)
        if path in self.by_path:
            return self.by_path[path]
        provider = provider_id(url)
        if provider:
            return self.by_provider.get(provider, provider)
        info = self.info.get(tvg_id.split("@")[0].lower())
        if info:
            return cell(info["id"], 100)
        codes = {c.upper() for c in re.split(r"[;,/ ]+", row["country"]) if COUNTRY_CODE.fullmatch(c)}
        named = {self.by_name.get((code, name_key(row["name"]))) for code in codes} - {None}
        return cell(named.pop(), 100) if len(named) == 1 else ""

    def _flag(self, row: dict, info: dict) -> None:
        """Moves the row when iptv-org blocklists the channel or marks it NSFW (_nsfw)."""
        blocked = self.blocked.get(info["id"].lower())
        if self._nsfw(info):
            _to_nsfw(row)
        elif blocked and row["_bucket"] == "public":
            row["_bucket"], row["reason"] = "private", cell(f"blocklist:{blocked}")

    def apply(self, row: dict, tvg_ids: list[str], names: Iterable[str] = ()) -> None:
        """Sets row["channel"] (keyed by the first copy's tvg-id that names a channels.json id); a blocklisted or NSFW
        channel, named by the key, by any copy's tvg-id or as the one iptv-org channel on the row's host+path (keying or
        not: by_path), moves the row out of public (NSFW out of private too); a row
        whose key names no channels.json channel moves to nsfw when its name or any copy's name (names) is an NSFW
        channel's name or alt name; empty country and category cells are filled from channels.json."""
        row["channel"] = self.key(row, next((t for t in tvg_ids if self.info.get(t.split("@")[0].lower())), ""))
        named = [self.info.get(k.split("@")[0].lower()) for k in [row["channel"], *tvg_ids]]
        path = _host_path(row["url"])
        neighbour = self.path_neighbour.get(path, "")
        for info in filter(None, named + [self.info.get(neighbour.split("@")[0].lower())]):
            self._flag(row, info)
        # The owner's rulings follow the channel's own URLs, never a host+path neighbour: the owner rules one channel,
        # while iptv-org's flags (above) may demote a whole shared path, failing safe.
        path_keyed = row["url"] not in self.by_url and path in self.by_path
        if any(_owner_nsfw(k) for k in ([] if path_keyed else [row["channel"]]) + list(tvg_ids)):
            _to_nsfw(row)
        info = named[0]
        if info is None:
            if any(name_key(n) in self.nsfw_names for n in [row["name"], *names]):
                _to_nsfw(row)
            return
        if row["country"] in ("", "-") and isinstance(info.get("country"), str):
            row["country"] = cell(info["country"])
        if row["category"] in ("", "-") and isinstance(info.get("categories"), list):
            row["category"] = cell(";".join(str(c) for c in info["categories"]))  # NSFW ones moved by _flag
