"""Bucket rules for candidate streams (Nuvio-Project Spec 60 D1, D9, D12).

Every candidate row lands in exactly one bucket; nothing is dropped:
  public   - releasable: passes every rule below AND the allowlist (allowlist.py), and carries no query string
             unless iptv-org lists that exact URL (D15); reason = the admitting criterion
  private  - kept, never published: subscriber credentials, pay-channel or pirate restreams, DRM, non-HTTP,
             URLs minted for one requester, every row the allowlist does not admit (unreviewed-host), and admitted
             rows with parameters (unreviewed-query)
  nsfw     - kept, never published, in a file of its own

Rules match the row's own URL, name, category and source page. A list's notes often describe rows inside it
("contains NSFW, exclude"), so notes only count for DRM and minted URLs on a single stream row. The deny rules below
stay as a second filter behind the allowlist; url_rejection() also decides which iptv-org URLs vouch for a host.
Query strings: a URL iptv-org does not list verbatim with a query is private whatever its keys (D15,
has_parameters); token_shaped judges paths, fragments and the other published cells (D16).

One URL can be found several times (copies). A verdict about the stream itself (its URL, DRM, minted notes, the
allowlist, NSFW) holds for every copy; a verdict about one copy only (it came from a listed pirate list or a dynamic
source, or its own headers/notes/source cell carry a credential or token) yields to a clean public copy, whose cells
are the ones published (merge()).
"""
import base64
import binascii
import functools
import json
import re
from collections.abc import Iterable, Mapping
from typing import NamedTuple
from urllib.parse import SplitResult, unquote, urlsplit

import egress
from allowlist import Allowlist, has_suffix, split_url

# Subscriber credentials in the URL (Xtream / Stalker panels, personal tokens). Xtream's short form
# host/<user>/<pass>/<id> has no generic pattern: it also matches official CDNs (TVP's tokenizer API,
# .../hls/8036/8036.m3u8), so the host list below and the allowlist are the defence for it. "p=" alone matches
# broadcaster APIs. The URL-shaped alternatives (user:pass@host, Xtream) start at any scheme, not only at the text's
# start, so an embedded URL counts too.
CREDENTIAL = re.compile(
    r"(?<![a-z0-9+.-])[a-z][a-z0-9+.-]*://[^/@?#\s]+@|"
    # nginx merges slashes, so //live/u/p/1 plays like /live/u/p/1
    r"(?<![a-z0-9+.-])https?://[^/?#\s]+/+(?:live|movie|series|timeshift)/+[^/?#]+/+[^/?#]+/+\d+(?:\.\w+)?(?:$|[?&#\s])|"
    r":2546[13]\b|/line/|/get\.php|[?&]mac=|play_token|[?&]ticket=|X-Plex-Token=|"
    r"[?&](?:username|password|pass|pwd|passwd|secret)=|"
    # Tvheadend's stream API on any port: a personal TV box or headend re-serving its tuner, not a broadcaster.
    r"/stream/channel(?:id|number)?/[0-9a-f]+(?:$|\?)",
    re.IGNORECASE,
)

# A URL can carry another one in an encoded layer: iptv-org listed tvstitch.com URLs whose base64 ?source= held a pay
# restream's per-subscriber ip/id/secret and a JWT with the subscriber's phone number. CREDENTIAL and these claims
# are also searched in the decoded layers (egress.layers, egress.decoded_runs).
JWT_PAYLOAD = re.compile(r"\.(eyJ[\w-]+)")  # anchored on the payload's "." (not in the run): linear
PERSONAL_CLAIM = re.compile(r"phone|mobile|msisdn|e?mail|^tel$|^(?:client_?)?ip$|^user_?(?:id|name)$|^uid$",
                            re.IGNORECASE)
PERSONAL_VALUE = re.compile(r"[^@\s]+@[^@\s]+\.[a-z]{2,}|\+\d[\d -]{7,}\d", re.IGNORECASE)  # e-mail, +phone

# Pay-channel restreams, pirate panels and third-party proxies named by the Spec 60 research
# (R1 final report section c, W3 section 8 scope review). Host tokens match with boundaries (so
# 102.129.84.20 does not catch 102.129.84.200); path entries (with "/") match as plain substrings, and an entry
# ending in "*" is a host-label prefix (ythls* = ythls., ythlsgo., ythls-v2. ...).
PRIVATE_HOSTS = (
    "allinonereborn", "jprdigital", "ridsys.in", "channelsarabia.xyz", "evrenesoglu99.click", "fptplay53",
    "dethich", "freem3u", "hoiquan", "moveonjoy", "gammacdn", "trxdnscloud.ru", "185.95.184.33",
    "freechannelsonly.xyz", "163.172.39.215", "rb-group-server.com", "xtreamiptv.xyz", "aflaxtv.xyz",
    "tvmoderne.ca", "xcpro.biz.id", "backup.760515.xyz", "102.129.84.20", "45.159.95.10", "luongz",
    "utako.moe", "ythls*", "api.marvelly.com.ng", "free.fullspeed.tv", "cors-proxy.elfsight.com",
    # Whole lists the research found to be credential, pay-restream or DRM-key collections.
    "saeidrahmanbd/bdix", "bplaytv/", "zokerpunk", "thilinam99", "yossipr", "kurdishiptvchannels",
    "verbosling", "m3u.su",
)


def _host_pattern(h: str) -> re.Pattern:
    if "/" in h:
        return re.compile(re.escape(h))
    if h.endswith("*"):
        return re.compile(r"(?<![\w-])" + re.escape(h[:-1]))
    return re.compile(r"(?<![\w-])" + re.escape(h) + r"(?![\w-])")


_HOST_PATTERNS = tuple(_host_pattern(h) for h in PRIVATE_HOSTS)

# NSFW by URL, name or category. "adult" alone is not used: Adult Swim is a cartoon channel.
NSFW_URL = re.compile(
    r"\bxxx\b|/xxx\.m3u|categories/xxx|porn|erotic|\bspicy\b|playboy|hustler|brazzers|visit-x|redlight|"
    r"\bnsfw\b|drsof1968",
    re.IGNORECASE,
)
NSFW_NAME = re.compile(
    r"xxx|porn|erotic|\bspicy\b|playboy|hustler|brazzers|visit-x|redlight|\bnsfw\b|dorcel|penthouse|"
    r"vivid ?tv|babes ?tv|babestation|18\+",
    re.IGNORECASE,
)
NSFW_CATEGORIES = {"xxx", "adult", "erotic", "nsfw"}
ADULT_WORD = re.compile(r"\badult\b(?!\s*swim)", re.IGNORECASE)  # free-text group-titles ("Adult Channels")

DRM_SCHEMES = r"widevine|clearkey|playready|fairplay"
DRM = re.compile(DRM_SCHEMES + r"|sample-aes|\bcenc\b|license_url|kodiprop|\bdrm\b", re.IGNORECASE)
# DRM named in a stream URL's path (/LA7D/DRM/HLS/, live_drm, cmaf_cenc00, playlist_cbcs.mpd): an encryption scheme
# there is a variant name; "_" and digits are separators in a path. Judged on URLs iptv-org does not list verbatim
# (D16): iptv-org vets its own.
DRM_PATH = re.compile(DRM_SCHEMES + r"|(?<![a-z])(?:drm|cenc|cbcs)(?![a-z])", re.IGNORECASE)
# Negated mentions ("non-DRM variant", "DRM-free") are removed before DRM is searched, so a note that says
# both "FairPlay DRM" and "non-DRM qxa returns 403" still counts as DRM. A negated "DRM-free" ("not", "isn't",
# "no longer", "never") is not a negation.
NOT_DRM = re.compile(r"(?<!not )(?<!n't )(?<!n\u2019t )(?<!longer )(?<!never )\bdrm[- ]free\b|"
                     r"\b(?:no|not|non|without)[- ]drm\b(?![- ]free)", re.IGNORECASE)

# Minted URLs (D12): made for one requester, possibly binding its IP (a TVP path token minted by the research
# fetches held this machine's IP). Spec 60 W3: never publish them; recipes resolve them on the viewer's device.
# 1. Token-shaped URLs, also percent-encoded (token_shaped): a signing/session key (TOKEN_KEYS) or one of the
#    TOKEN_URL shapes. Token shapes found after D18 are patched here as accepted D16 residual (Spec 60 D18).
# Query, fragment or path parameter keys: Akamai, Wowza, Wangsu ws*, Tencent tx*, S3, MediaTailor aws.sessionId,
# ad-stitcher streaming ids. A key is read possessively (PARAMETER_KEY) and judged by _token_key, so a long run of
# "token" is scanned once, not once per occurrence.
PARAMETER_KEY = re.compile(r"[?&;/~#]([a-z0-9_.-]*+)=", re.IGNORECASE)
TOKEN_KEYS = frozenset((
    "hdnts", "hdnea", "hdntl", "__hdnea__", "tkn", "wmsauthsign", "jwt", "auth", "auth_key", "policy", "signature",
    "key-pair-id", "expires", "exp", "sig", "sign", "md5", "hash", "hmac", "acl", "validto", "nva", "nvb", "sid",
    "session", "_lsu_sa_", "wssecret", "wstime", "txsecret", "txtime", "__gda__", "ec_secure", "st", "secure", "nonce"))
# Fullmatched against a key; each alternative's run ends in a literal, so linear.
TOKEN_KEY_SHAPES = re.compile(r"[a-z_.]*sessionid|[a-z_.-]*api[-_]?key|[a-z_.]*streaming_?id|x-amz-[a-z-]+")
# An epoch+hash pair (e=<epoch>&h=).
_SIGNED_PAIR = r"[?&]e=\d{9,}&h=|[?&]h=[0-9a-f]+&e=\d{9,}"
# A query value that is an IP address, IPv4 (with a port) or IPv6 (an ad stitcher's ads.ip=<requester>: minted for
# whoever built the list), ending where the value does (also before a quote or a space: cells hold JSON and free
# text). Linear: the key run holds no start character and the value groups are bounded.
_IP_VALUE = (r"[?&;][^=&#;?]*=(?:(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?|\[?(?:(?:[0-9a-f]{1,4}:){4,7}[0-9a-f]{1,4}|"
             r"(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6})?::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6})?)\]?)(?![\w.:-])")
# Path-token markers (/token/, CloudFront's /_token/v1.<epoch>.<hmac>/), a path segment of base64 JSON
# (Rakuten/MediaTailor bitok/eyJ<session>), /expires/<epoch>, DAI pod-serving (/stream/<uuid>) and MediaTailor session
# paths, Dailymotion sec(...) paths, Wowza session chunklists.
_PATH_MARKERS = (r"/[_-]?(?:token|tkn|session|signature)/|/eyJ[\w-]{8,}|/expires?/\d|/stream/[0-9a-f]{8}-[0-9a-f-]{27}|"
                 r"/v1/manifest/[^/]+/[^/]+/[0-9a-f]{8}-[0-9a-f-]{27}/|/sec\d?\(|chunklist_w\d")
# A hex digest segment, then a number (webcaster.pro free_<hash>/<id>/1080p/<md5>/<expiry>.m3u8; key-bound restreams
# /live/<32hex>/<channel>.m3u8). Measured 2026-11-07 (run 11): 3 public non-exact rows, all webcaster.pro.
_SIGNED_PATH = r"/[0-9a-f]{32}/\d++(?=[./]|$)"
# A JWT anywhere, by its payload ("tok_eyJ<header>.eyJ<payload>" too): "." is not in the run, so linear.
_JWT = r"\.eyJ[\w-]{8,}"
TOKEN_URL = re.compile("|".join((_SIGNED_PAIR, _IP_VALUE, _PATH_MARKERS, _SIGNED_PATH, _JWT)), re.IGNORECASE)
# 2. A stream row's notes saying its URL is bound to the requester or expires.
MINTED_NOTES = re.compile(
    r"\bip[- ]?(?:bound|locked|restricted|tied)|client ?ip|session[- ]?(?:signed|bound|url|token|id|chunklist)|minted|"
    r"expir\w*|short[- ]lived",
    re.IGNORECASE,
)
# 3. Provenance, an allowlist (Arshad 2026-11-07, after two review rounds found API-shape lists incomplete): a stream
#    row was not minted for our fetch only when it was recorded directly (its source page is its own URL) or copied
#    from static hosting that serves the same file to everyone. Anything read from a broadcaster page, API, XHR
#    endpoint, redirector or other web host is minted; a missing static host only sends rows private.
STATIC_SOURCES = (
    "raw.githubusercontent.com", "gist.githubusercontent.com", "github.com", "gist.github.com", "api.github.com",
    "github.io", "gitlab.com", "gitlab.io", "bitbucket.org", "codeberg.org", "cdn.jsdelivr.net", "pastebin.com",
    "pastecode.dev", "i.mjh.nz",
)
# D14 (Arshad 2026-11-07): M3U list files on these web hosts, byte-identical on refetch, are static; nothing else there.
STATIC_M3U_HOSTS = ("www.apsattv.com", "www.tdtchannels.com", "m3u.cl")
M3U_FILE = re.compile(r"\.m3u8?$", re.IGNORECASE)
REDIRECT_PATH = re.compile(r"^/\.r/")  # i.mjh.nz/.r/<slug> answers each requester with a fresh redirect

SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)

# Rows of these kinds point at many streams; every other kind is one stream.
LIST_KINDS = ("list-endpoint", "api")


class Verdict(NamedTuple):
    bucket: str
    reason: str
    copy_only: bool = False  # private only because of this copy's source or cells (module docstring)


# The two orders of the four verdict classes, lowest first; they differ only in where public stands. Across copies
# (merge) a clean public copy beats a fault of one other copy only; within one copy (stricter) any fault beats public.
# "private" is private for the stream itself (its URL, DRM, minted notes, the allowlist), "private-copy" for this copy
# only (its source or its cells).
MERGE_ORDER = ("private-copy", "public", "private", "nsfw")
FAULT_ORDER = ("public", "private-copy", "private", "nsfw")


def _class(verdict: Verdict) -> str:
    return "private-copy" if verdict.bucket == "private" and verdict.copy_only else verdict.bucket


def rank(verdict: Verdict) -> int:
    """Merge rank, highest wins (MERGE_ORDER)."""
    return MERGE_ORDER.index(_class(verdict))


def _names_a_person(claims: object) -> bool:
    """Whether decoded JWT claims, at any depth, name a person: a personal claim key with a value, or a value shaped
    like an e-mail address or an international phone number."""
    stack = [claims]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for key, value in node.items():
                if PERSONAL_CLAIM.search(str(key)) and value not in (None, "", 0, [], {}):
                    return True
                stack.append(value)
        elif isinstance(node, list):
            stack.extend(node)
        elif isinstance(node, str) and PERSONAL_VALUE.fullmatch(node.strip()):
            return True
    return False


def _personal_jwt(text: str) -> bool:
    """Whether the text holds a JWT whose payload names a person."""
    for payload in JWT_PAYLOAD.findall(text):
        try:
            claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        except (binascii.Error, ValueError, RecursionError):  # UnicodeDecodeError, JSONDecodeError: ValueErrors
            continue
        if _names_a_person(claims):
            return True
    return False


@functools.lru_cache(maxsize=1 << 18)
def hidden_credential(text: str) -> bool:
    """A credential or a personal JWT in the text (a URL or a published cell) or any of its decoded layers (cached:
    copies repeat URLs and source pages)."""
    for layer in egress.layers(text):
        for chunk in (layer, *egress.decoded_runs(layer)):
            text = chunk.decode("utf-8", "replace")
            if CREDENTIAL.search(text) or _personal_jwt(text):
                return True
    return False


def url_rejection(url: str) -> tuple[str, str] | None:
    """(bucket, reason) when the URL alone rules a row out (NSFW, scheme, credential, listed host), else None."""
    if NSFW_URL.search(url):
        return "nsfw", "nsfw"
    if not SCHEME.match(url):
        return "private", "no-scheme"
    if not re.match(r"https?://", url, re.IGNORECASE):
        return "private", "non-http"
    if hidden_credential(url):
        return "private", "credential"
    lowered = url.lower()
    for host, pattern in zip(PRIVATE_HOSTS, _HOST_PATTERNS):
        if pattern.search(lowered):
            return "private", f"listed:{host}"
    return None


def _token_key(key: str) -> bool:
    """Whether a parameter key signs or names a session: TOKEN_KEYS, TOKEN_KEY_SHAPES, or "token" followed only by
    [a-z0-9_] (v2token, token_id, wowzatokenhash; tested at the last "token", which any earlier match implies)."""
    key = key.lower()
    _, token, tail = key.rpartition("token")
    return (key in TOKEN_KEYS or bool(TOKEN_KEY_SHAPES.fullmatch(key))
            or bool(token and re.fullmatch(r"[a-z0-9_]*", tail)))


@functools.lru_cache(maxsize=1 << 18)
def token_shaped(text: str) -> bool:
    """A token key or a TOKEN_URL shape in the text or its percent-decoded layers (an encoded &apikey%3D is still a
    key)."""
    for layer in egress.layers(text):
        decoded = layer.decode("utf-8", "replace")
        if TOKEN_URL.search(decoded) or any(_token_key(key) for key in PARAMETER_KEY.findall(decoded)):
            return True
    return False


def nsfw_category(text: str) -> bool:
    """Whether a category cell names adult content: a listed token, an NSFW name term, or the word "adult" (not Adult
    Swim). Pulled lists' group-titles are free text ("XXX Movies", "Adult Channels")."""
    tokens = {c.strip() for c in re.split(r"[;,/|]", text.lower())}
    return bool(tokens & NSFW_CATEGORIES or NSFW_NAME.search(text) or ADULT_WORD.search(text))


def vouches(url: str) -> bool:
    """Whether an iptv-org URL may vouch for its host: a credential panel's URL must not admit its siblings."""
    return url_rejection(url) is None


def _static_source(row: Mapping[str, str]) -> bool:
    source = row["source_page"]
    if source == row["url"]:
        return True
    # Exactly one URL: free text or a second URL after it could name the dynamic step the stream came from.
    if not re.fullmatch(r"https?://\S+", source, re.IGNORECASE) or source.count("://") != 1:
        return False
    split = split_url(source)
    if split is None:
        return False
    host, _, segments = split
    path = unquote("/" + "/".join(segments))  # %2Er is the same redirector as .r
    if host in STATIC_M3U_HOSTS:
        return bool(M3U_FILE.search(path))
    return has_suffix(host, STATIC_SOURCES) and not REDIRECT_PATH.match(path)


def _split(url: str) -> SplitResult | None:
    """urlsplit's parts, None when it cannot read the URL (an unbalanced "[")."""
    try:
        return urlsplit(url)
    except ValueError:
        return None


def has_parameters(url: str) -> bool:
    """Whether the URL carries parameters (D15): a non-empty query, or ";", "?" or a Kodi "|" suffix in its path or a
    percent-decoded layer of it. A fragment is never sent to the server and stays (token_shaped reads its keys)."""
    parts = _split(url)
    return parts is None or bool(parts.query) or any(mark in layer for layer in egress.layers(parts.path)
                                                     for mark in (b";", b"?", b"|"))


def _listed_source(source: str) -> str | None:
    """The PRIVATE_HOSTS entry a row's source page matches: rows copied from a listed pirate list stay private."""
    lowered = source.lower()
    return next((host for host, pattern in zip(PRIVATE_HOSTS, _HOST_PATTERNS) if pattern.search(lowered)), None)


def verdict(row: Mapping[str, str], allow: Allowlist) -> Verdict:
    """The verdict for one copy (extract_research.COLUMNS). NSFW is checked first so it never mixes into private;
    checks about the stream itself run before checks about this copy, so a copy failing both reports the former. The
    allowlist and the query check (D15) come last: they read only the URL, so every copy of it fails them alike and
    the merged row stays private whichever reason it reports."""
    if NSFW_NAME.search(row["name"]) or nsfw_category(row["category"]) or NSFW_URL.search(row["source_page"]):
        return Verdict("nsfw", "nsfw")
    url = row["url"]
    rejected = url_rejection(url)
    if rejected:
        return Verdict(*rejected)
    stream = row["kind"] not in LIST_KINDS
    # iptv-org published this exact string, so it was not minted for our fetches alone.
    listed_by_iptv_org = url in allow.urls
    # DRM is a property of the stream itself; for a list endpoint the notes describe its contents.
    parts = _split(url)
    if stream and (DRM.search(row["format"]) or DRM.search(NOT_DRM.sub("", row["name"]))
                   or DRM.search(NOT_DRM.sub("", row["notes"]))
                   or (not listed_by_iptv_org and DRM_PATH.search(parts.path if parts else url))):
        return Verdict("private", "drm")
    if not listed_by_iptv_org and (token_shaped(url) or (stream and MINTED_NOTES.search(row["notes"]))):
        return Verdict("private", "minted")
    listed = _listed_source(row["source_page"])
    if listed:
        return Verdict("private", f"listed:{listed}", copy_only=True)
    # Every other published cell: a credential or token written into any of them is published too. A list's notes
    # describe its contents ("contains :25461 entries"), and a directly recorded row's source is its URL, judged above
    # and by the exact-iptv-org exemption.
    columns = ("name", "country", "language", "category", "kind", "format", "headers", "geo_hint") + (
        ("notes",) if stream else ()) + (("source_page",) if row["source_page"] != url else ())
    for column in columns:
        if hidden_credential(row.get(column, "-")):
            return Verdict("private", "credential", copy_only=True)
        if token_shaped(row.get(column, "-")):
            return Verdict("private", "minted", copy_only=True)
    if stream and not listed_by_iptv_org and not _static_source(row):
        return Verdict("private", "minted", copy_only=True)
    criterion = allow.admit(url)
    if criterion is None:
        return Verdict("private", "unreviewed-host")
    if not listed_by_iptv_org and has_parameters(url):
        return Verdict("private", "unreviewed-query")
    return Verdict("public", criterion)


def bucket(row: Mapping[str, str], allow: Allowlist) -> tuple[str, str]:
    """(bucket, reason) for one copy."""
    return verdict(row, allow)[:2]


def _severity(verdict: Verdict) -> int:
    return FAULT_ORDER.index(_class(verdict))


def stricter(first: Verdict | None, second: Verdict | None) -> Verdict | None:
    """The stricter of two verdicts for one copy (None = no verdict), by FAULT_ORDER; across copies merge() ranks
    instead."""
    if first is None or (second is not None and _severity(second) > _severity(first)):
        return second
    return first


def merge(copies: Iterable[tuple[Mapping[str, str], str, Verdict]]) -> dict[str, dict]:
    """Dedupes (row, origin, verdict) copies by exact URL. The highest-ranked verdict wins (rank()) and its copy's cells
    are kept; the first copy wins a tie. seen_in lists every distinct origin, first seen first; _tvg_ids lists every
    distinct non-empty tvg_id of any copy, first seen first."""
    kept: dict[str, dict] = {}
    seen: dict[str, dict[str, None]] = {}
    tvg_ids: dict[str, dict[str, None]] = {}
    for row, where, found in copies:
        url = row["url"]
        old = kept.get(url)
        if old is None or rank(found) > old["_rank"]:
            kept[url] = {**row, "reason": found.reason, "_bucket": found.bucket, "_rank": rank(found)}
        seen.setdefault(url, {})[where] = None
        if row.get("tvg_id"):
            tvg_ids.setdefault(url, {})[row["tvg_id"]] = None
    for url, row in kept.items():
        row["seen_in"] = ",".join(seen[url])
        row["_tvg_ids"] = list(tvg_ids.get(url, {}))
    return kept
