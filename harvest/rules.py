"""Bucket rules for candidate streams (Nuvio-Project Spec 60 D1, D9, D12).

Every candidate row lands in exactly one bucket; nothing is dropped:
  public   - releasable: passes every rule below AND the allowlist (allowlist.py); reason = the admitting criterion
  private  - kept, never published: subscriber credentials, pay-channel or pirate restreams, DRM, non-HTTP,
             URLs minted for one requester, and every row the allowlist does not admit (unreviewed-host)
  nsfw     - kept, never published, in a file of its own

Rules match the row's own URL, name, category and source page. A list's notes often describe rows inside it
("contains NSFW, exclude"), so notes only count for DRM and minted URLs on a single stream row. The deny rules below
stay as a second filter behind the allowlist; url_rejection() also decides which iptv-org URLs vouch for a host.
"""
import re
from collections.abc import Mapping
from urllib.parse import unquote

from allowlist import Allowlist, split_url

# Subscriber credentials in the URL (Xtream / Stalker panels, personal tokens). Xtream's short form
# host/<user>/<pass>/<id> has no generic pattern: it also matches official CDNs (TVP's tokenizer API,
# .../hls/8036/8036.m3u8), so the host list below and the allowlist are the defence for it. "p=" alone matches
# broadcaster APIs.
CREDENTIAL = re.compile(
    r"^[a-z][a-z0-9+.-]*://[^/@?#]+@|"  # user:pass@host
    r"^https?://[^/]+/(?:live|movie|series|timeshift)/[^/?#]+/[^/?#]+/\d+(?:\.\w+)?(?:$|\?)|"  # Xtream
    r":2546[13]\b|/line/|/get\.php|[?&]mac=|play_token|[?&]ticket=|X-Plex-Token=|"
    r"[?&](?:username|password|pass|pwd|passwd)=|"
    # Tvheadend's stream API on any port: a personal TV box or headend re-serving its tuner, not a broadcaster.
    r"/stream/channel(?:id|number)?/[0-9a-f]+(?:$|\?)",
    re.IGNORECASE,
)

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

DRM = re.compile(r"widevine|clearkey|playready|fairplay|sample-aes|\bcenc\b|license_url|kodiprop|\bdrm\b",
                 re.IGNORECASE)
# Negated mentions ("non-DRM variant", "DRM-free") are removed before DRM is searched, so a note that says
# both "FairPlay DRM" and "non-DRM qxa returns 403" still counts as DRM. A negated "DRM-free" ("not", "isn't",
# "no longer", "never") is not a negation.
NOT_DRM = re.compile(r"(?<!not )(?<!n't )(?<!n\u2019t )(?<!longer )(?<!never )\bdrm[- ]free\b|"
                     r"\b(?:no|not|non|without)[- ]drm\b(?![- ]free)", re.IGNORECASE)

# Minted URLs (D12): made for one requester, possibly binding its IP (a TVP path token minted by the research
# fetches held this machine's IP). Spec 60 W3: never publish them; recipes resolve them on the viewer's device.
# 1. Token-shaped URLs: signing/session query or path keys (Akamai, Wowza, Wangsu ws*, Tencent tx*, S3, MediaTailor
#    aws.sessionId), path-token markers, DAI pod-serving (/stream/<uuid>) and MediaTailor session paths,
#    Dailymotion sec(...) paths, Wowza session chunklists, an epoch+hash pair (e=<epoch>&h=), JWTs anywhere.
TOKEN_URL = re.compile(
    r"[?&;/~](?:hdnts|hdnea|hdntl|__hdnea__|[a-z_-]*token|tkn|wmsauthsign|wowzatoken\w*|jwt|auth|auth_key|policy|"
    r"signature|key-pair-id|expires|exp|sig|sign|md5|hash|hmac|acl|validto|nva|nvb|sid|session|[a-z_.]*sessionid|"
    r"_lsu_sa_|x-amz-[a-z-]+|api[-_]?key|__token__|ws(?:secret|time)|tx(?:secret|time)|__gda__|ec_secure|st|secure|"
    r"nonce)=|[?&]e=\d{9,}&h=|[?&]h=[0-9a-f]+&e=\d{9,}|"
    r"/(?:token|tkn|session|signature)/|/expires?/\d|/stream/[0-9a-f]{8}-[0-9a-f-]{27}|"
    r"/v1/manifest/[^/]+/[^/]+/[0-9a-f]{8}-[0-9a-f-]{27}/|/sec\d?\(|chunklist_w\d|eyJ[\w-]{8,}\.eyJ",
    re.IGNORECASE,
)
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
REDIRECT_PATH = re.compile(r"^/\.r/")  # i.mjh.nz/.r/<slug> answers each requester with a fresh redirect

SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)

# Higher wins when two rows share a URL (extract_research.merge).
RANK = {"public": 0, "private": 1, "nsfw": 2}
# Rows of these kinds point at many streams; every other kind is one stream.
LIST_KINDS = ("list-endpoint", "api")


def url_rejection(url: str) -> tuple[str, str] | None:
    """(bucket, reason) when the URL alone rules a row out (NSFW, scheme, credential, listed host), else None."""
    if NSFW_URL.search(url):
        return "nsfw", "nsfw"
    if not SCHEME.match(url):
        return "private", "no-scheme"
    if not re.match(r"https?://", url, re.IGNORECASE):
        return "private", "non-http"
    if CREDENTIAL.search(url):
        return "private", "credential"
    lowered = url.lower()
    for host, pattern in zip(PRIVATE_HOSTS, _HOST_PATTERNS):
        if pattern.search(lowered):
            return "private", f"listed:{host}"
    return None


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
    return any(host == s or host.endswith("." + s) for s in STATIC_SOURCES) and not REDIRECT_PATH.match(path)


def _minted(row: Mapping[str, str], stream: bool) -> bool:
    return bool(TOKEN_URL.search(row["url"])
                or (stream and (MINTED_NOTES.search(row["notes"]) or not _static_source(row))))


def _listed_source(source: str) -> str | None:
    """The PRIVATE_HOSTS entry a row's source page matches: rows copied from a listed pirate list stay private."""
    lowered = source.lower()
    return next((host for host, pattern in zip(PRIVATE_HOSTS, _HOST_PATTERNS) if pattern.search(lowered)), None)


def bucket(row: Mapping[str, str], allow: Allowlist) -> tuple[str, str]:
    """Returns (bucket, reason) for one row (extract_research.COLUMNS). NSFW is checked first so it never mixes into
    private."""
    categories = {c.strip() for c in re.split(r"[;,/|]", row["category"].lower())}
    if NSFW_NAME.search(row["name"]) or categories & NSFW_CATEGORIES or NSFW_URL.search(row["source_page"]):
        return "nsfw", "nsfw"
    url = row["url"]
    rejected = url_rejection(url)
    if rejected:
        return rejected
    listed = _listed_source(row["source_page"])
    if listed:
        return "private", f"listed:{listed}"
    # The other published cells: a credential or token written into headers, a source page or a stream's notes is
    # published too. A list's notes describe its contents ("contains :25461 entries"), and a directly recorded row's
    # source is its URL, judged above and by the exact-iptv-org exemption below.
    stream = row["kind"] not in LIST_KINDS
    columns = ("headers",) + (("notes",) if stream else ()) + (("source_page",) if row["source_page"] != url else ())
    for column in columns:
        if CREDENTIAL.search(row[column]):
            return "private", "credential"
        if TOKEN_URL.search(row[column]):
            return "private", "minted"
    # DRM is a property of the stream itself; for a list endpoint the notes describe its contents.
    if stream and (DRM.search(row["format"]) or DRM.search(NOT_DRM.sub("", row["name"]))
                   or DRM.search(NOT_DRM.sub("", row["notes"]))):
        return "private", "drm"
    # iptv-org published this exact string, so it was not minted for our fetches alone.
    if url not in allow.urls and _minted(row, stream):
        return "private", "minted"
    criterion = allow.admit(url)
    return ("public", criterion) if criterion else ("private", "unreviewed-host")
