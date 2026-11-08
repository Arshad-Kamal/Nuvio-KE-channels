#!/usr/bin/env python3
"""Probes a channel repo's pool and keeps per-URL state (Nuvio-Project Spec 71 M1.2).

Usage: monitor.py <repo> --budget SECONDS [--workers N] [--lookups N]

<repo> is the public checkout (it holds harvest/; pool: pool/streams.tsv) or the private repo (pool/private.tsv and
pool/nsfw.tsv); the kind is read from the repo, so no argument can mix the two. The monitor never changes membership:
it reads the pool and writes only monitor/state.tsv (url, state, since, class, slots) and monitor/cursor. Nothing a
server sent is written: cells are enums, dates and slot bits, every URL must be an in-scope pool URL, and a run that
breaks any of that writes nothing (exit 1). Output is aggregate counts, never a URL.

Scope (Spec 71 D2, D7, D8): http(s) only, no YouTube host, no credential, minted, non-http or listed reason, and no
fault rules.private_faults finds in the row but drm (D2 probes DRM rows), whatever its reason (a merged row's reason
names one: nsfw or drm hides a listed source or a minted provenance); a fault reason added later skips by default.
A listed host or list is rules.py's only defence against Xtream's short-form credential URLs (D17, D8); build_pool
refuses a listed list its rows could not show (D9).

FAST rows (D1): a jmp2.uk or i.mjh.nz URL naming a Pluto/Samsung/Roku/Plex channel is judged by its service's index
(listed / unlisted), plus a sample of US rows probed each run (fast_results); it is never probed in the ring.

Probe (Design 2): the row's URL with its headers cell (else an honest UA), an HLS master's first variant, then a range
of the segment three from the end; DASH and audio/video answers are judged on the first answer. Each host is looked up
once per run, before its rows' probes start, and connections go to the looked-up public address (Resolver). One
attempt per run.

States (D3): step(). Order of a run (D6): the FAST sample, the gone rows due this run (gone_due: weekly), then the ring
in URL-hash order from the cursor (ring), within a time budget (sweep).
"""
import argparse
import contextlib
import hashlib
import http.client
import json
import os
import queue
import random
import re
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from bisect import bisect_right
from collections import Counter, defaultdict, deque
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import date, datetime, timezone
from itertools import count
from pathlib import Path
from typing import NamedTuple
from urllib.parse import urljoin, urlsplit

import build_pool
import lists
from allowlist import has_suffix
from channels import provider_id
from extract_research import private_repo
from rules import private_faults

USER_AGENT = "Nuvio-KE-channels monitor (+https://github.com/Arshad-Kamal/Nuvio-KE-channels)"
SOCKET_TIMEOUT = 10  # per socket operation
PROBE_DEADLINE = 25  # whole probe once its host is looked up: connects, TLS, redirects, every step (Spec 71 M1.0)
PLAYLIST_CAP = 256 << 10  # a playlist cut here loses its partial last line
SEGMENT_BYTES = 1 << 16
BLOCK_PAGE_BYTES = 16 << 10  # block pages are small; the regex never scans a whole untrusted playlist-sized body
MASTER_HOPS = 2  # a master playlist may point at another master once
WORKERS = 128
PER_HOST = 4  # probes in flight per row host
DNS_LOOKUPS = 8  # lookups at once: a loaded resolver answers slowly and falsely (Spec 71 M1.2); `--lookups` tunes it
DNS_RETRY_PAUSE = 1.0
SAMPLE = 20  # FAST sample probes per service per run (D1)
STATES = ("alive", "suspect", "down", "gone", "blocked")
CLASSES = ("ok", "drm", "blocked", "down", "gone", "listed", "unlisted")
SUCCESS = frozenset(("ok", "drm", "listed"))
HARD = frozenset(("gone", "unlisted"))  # D3's hard last result: 404/410/NXDOMAIN, or the service dropped the id
WINDOWS = (14, 30)  # days failing before gone: with a hard last result, with any (doubled for "Not 24/7")
STATE_COLUMNS = ["url", "state", "since", "class", "slots"]
SLOTS = 8  # UTC 3-hour slots (D5)
RUNS_A_WEEK = 14  # D5: two runs a day, 12 hours apart (one before 12:00 UTC, one after)
STATE_FILE = Path("monitor") / "state.tsv"
CURSOR_FILE = Path("monitor") / "cursor"
KEY_LENGTH = 16

SKIP_REASONS = ("credential", "minted", "non-http", "no-scheme", "listed")
YOUTUBE_HOSTS = ("youtube.com", "youtu.be")
FAST_HOSTS = ("jmp2.uk", "i.mjh.nz")
FAST_SERVICES = tuple(lists.FAST_INDEXES)
SEND_HEADERS = ("Referer", "User-Agent", "Origin")
# Printable Latin-1 only: no control characters (no header splitting), nothing http.client cannot encode.
HEADER_VALUE = re.compile(r"[\x20-\x7e\xa0-\xff]{1,1000}")
BLOCKED_CODES = frozenset((401, 402, 403, 451))
GONE_CODES = frozenset((404, 410))
# SAMPLE-AES (any), or a Widevine / PlayReady / FairPlay key format; AES-128 with a key URI plays and is not DRM.
HLS_DRM = re.compile(rb'METHOD=SAMPLE-AES|KEYFORMAT="(?:urn:uuid:(?:edef8ba9|9a04f079)|com\.microsoft\.playready|'
                     rb'com\.apple\.streamingkeydelivery)', re.IGNORECASE)
DECOY_URL = re.compile(r"video_no_available", re.IGNORECASE)  # RAI's geo slate (Spec 60 R1 lane 15)
# Block pages lane 15 cites: Akamai's "Access Denied ... Reference #" (its page writes "Reference&#32;&#35;"), a
# country block, Cloudflare's error 1009.
BLOCK_PAGE = re.compile(rb"access denied.{0,4000}?reference(?:\s|&#32;)*(?:#|&#35;)|block access from your country|"
                        rb"error\s*(?:code:?\s*)?1009", re.IGNORECASE | re.DOTALL)
FMP4_BOXES = (b"ftyp", b"styp", b"moof", b"sidx")
# A body is text when its start (after a UTF-8 BOM and whitespace, lowercased) is a page or playlist opening, JSON, or
# all printable ASCII: several bytes each, so AES-128 ciphertext (random bytes) never reads as text, whatever its type.
TEXT_START = (b"<!", b"<?xml", b"<html", b"<head", b"<body", b"<h1", b"<title", b"<script", b"<error", b"#extm3u")
JSON_START = re.compile(rb'[\[{]\s*["\[{]')
TEXT_PROBE = 64


class MonitorError(Exception):
    """The run cannot go on, or would write something it must not; nothing is written."""


@dataclass(frozen=True)
class Row:
    url: str
    host: str  # the URL's lowercased host: the per-host cap's key
    key: str  # ring order: the URL's hash
    headers: tuple[tuple[str, str], ...]
    not247: bool
    us: bool  # its country cell names US (the FAST sample)
    service: str | None  # FAST index rows: the service and the provider id
    pid: str | None


@dataclass(frozen=True)
class Record:
    state: str
    since: date
    cls: str
    slots: str


# --- pool and scope ----------------------------------------------------------------------------------------------

def pool_paths(repo: Path) -> list[Path]:
    """The pool files of a repo, by its kind (build_pool.pool_files names them); a public checkout holding private
    files, or a private repo inside a public checkout, is refused (its state would be one commit from publication)."""
    files = build_pool.pool_files(repo, repo)
    if (repo / "harvest").is_dir():
        if files["private"].exists() or files["nsfw"].exists():
            raise MonitorError("the public checkout holds private pool files")
        return [files["public"]]
    try:
        private_repo(str(repo))
    except argparse.ArgumentTypeError as error:
        raise MonitorError(str(error)) from error
    return [files["private"], files["nsfw"]]


def ring_key(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:KEY_LENGTH]


def _headers(cell: str) -> tuple[tuple[str, str], ...]:
    """The request headers a headers cell names (Referer, User-Agent, Origin with clean values); others are dropped."""
    if not cell.startswith("{"):
        return ()
    try:
        found = json.loads(cell)
    except (ValueError, RecursionError):
        return ()
    if not isinstance(found, dict):
        return ()
    return tuple((name, value) for name, value in found.items()
                 if name in SEND_HEADERS and isinstance(value, str) and HEADER_VALUE.fullmatch(value))


def _skipped(reason: str) -> bool:
    return reason.split(":")[0] in SKIP_REASONS


def scoped(row: dict[str, str]) -> Row | None:
    """The Row to monitor, or None when the pool row is out of scope (module docstring)."""
    url = row["url"]
    if _skipped(row["reason"]) or not re.match(r"https?://", url, re.IGNORECASE):
        return None
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        parts.port  # noqa: B018  (raises on a bad port)
    except ValueError:
        return None
    listed_by_iptv_org = "iptv-org" in row["seen_in"].split(",")  # the merged row holds iptv-org's copy
    if not host or has_suffix(host, YOUTUBE_HOSTS) or any(
            fault.reason != "drm" for fault in private_faults(row, listed_by_iptv_org)):
        return None
    pid = provider_id(url)
    service = pid.split(":")[0] if pid else None
    fast = host in FAST_HOSTS and service in FAST_SERVICES  # i.mjh.nz/.r/ slugs are "mjh:": probed in the ring
    return Row(url=url, host=host, key=ring_key(url), headers=_headers(row["headers"]),
               not247="not 24/7" in row["notes"].lower(), us="US" in re.split(r"[;,\s]+", row["country"].upper()),
               service=service if fast else None, pid=pid if fast else None)


def load_rows(paths: Iterable[Path]) -> dict[str, Row]:
    """In-scope rows of the pool files by URL (a URL in two files: the first)."""
    rows: dict[str, Row] = {}
    for path in paths:
        if not path.exists():
            raise MonitorError(f"missing pool file {path.name}")
        try:
            for found in build_pool.read_tsv(path):
                row = scoped(found)
                if row is not None:
                    rows.setdefault(row.url, row)
        except KeyError as error:
            raise MonitorError(f"{path.name} lacks column {error}") from error
    return rows


# --- probing -----------------------------------------------------------------------------------------------------

class ResolveError(Exception):
    """A host that cannot be used: cls "gone" (no such name) or "down" (a lookup failure, a non-public address).
    Not an OSError, so urllib relays it unwrapped."""

    def __init__(self, cls: str, detail: str):
        super().__init__(detail)
        self.cls = cls


class _Outcome(Exception):
    """A probe's class, decided before its last step (not an OSError: urllib relays it unwrapped)."""

    def __init__(self, cls: str):
        super().__init__(cls)
        self.cls = cls


def _lookup(host: str) -> list[str]:
    return [info[4][0] for info in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)]


class Resolver:
    """Each host is looked up once per run (concurrent askers wait for the first); a temporary failure (EAI_AGAIN) is
    retried once. Only EAI_NONAME (no such name) reads gone: EAI_NODATA rose with resolver load. A host with any
    non-public address is refused (lists.public_address) and connections go to the addresses looked up here, so a
    second lookup cannot answer differently. Lookups from probes (a redirect's new host) run at most `lookups` at once,
    apart from sweep's lookup stage (warm), which its own threads bound: queued behind the stage, a probe's redirect
    lookup ran out its deadline."""

    def __init__(self, lookup: Callable[[str], list[str]] = _lookup,
                 public: Callable[[str], bool] = lists.public_address, retry_pause: float = DNS_RETRY_PAUSE,
                 lookups: int = DNS_LOOKUPS):
        self._lookup, self._public, self._pause = lookup, public, retry_pause
        self._lock = threading.Lock()
        self._lookups = threading.BoundedSemaphore(lookups)
        self._answers: dict[str, tuple[threading.Event, list]] = {}

    def addresses(self, host: str, gated: bool = True) -> list[str]:
        host = host.lower()
        with self._lock:
            entry = self._answers.get(host)
            first = entry is None
            if first:
                entry = self._answers[host] = (threading.Event(), [])
        done, answer = entry
        if first:
            try:
                answer.append(self._resolve(host, gated))
            except Exception as error:  # a bug: every asker gets one, so sweep counts it and records no result
                answer.append(error)
                raise
            finally:
                done.set()
        else:
            done.wait()
        stored = answer[0]
        # a fresh exception per asker: one shared instance would grow its traceback with every raise
        if isinstance(stored, ResolveError):
            raise ResolveError(stored.cls, str(stored))
        if isinstance(stored, Exception):
            raise RuntimeError(f"lookup raised {type(stored).__name__}")
        return stored

    def warm(self, host: str) -> None:
        """Looks the host up now (sweep's lookup stage); a failure waits in the cache for the probe."""
        try:
            self.addresses(host, gated=False)
        except ResolveError:
            pass

    def _resolve(self, host: str, gated: bool) -> list[str] | ResolveError:
        for attempt in range(2):
            try:
                with self._lookups if gated else contextlib.nullcontext():
                    found = self._lookup(host)
                break
            except socket.gaierror as error:
                if error.errno == socket.EAI_NONAME:
                    return ResolveError("gone", "no such name")
                if error.errno != socket.EAI_AGAIN or attempt:
                    return ResolveError("down", f"lookup failed ({error.errno})")
                time.sleep(self._pause)
            except (OSError, UnicodeError) as error:
                return ResolveError("down", f"lookup failed ({type(error).__name__})")
        try:
            if not found or not all(self._public(address) for address in found):
                return ResolveError("down", "not a public address")
        except ValueError:
            return ResolveError("down", "not an address")
        return found

    def connect(self, address: tuple[str, int], timeout: object = socket._GLOBAL_DEFAULT_TIMEOUT,
                source_address: tuple[str, int] | None = None) -> socket.socket:
        """http.client's _create_connection: the host's looked-up addresses, tried in order."""
        host, port = address
        error: OSError | None = None
        for ip in self.addresses(host):
            try:
                return socket.create_connection((ip, port), timeout, source_address)
            except OSError as failed:
                error = failed
        raise error  # addresses() never returns an empty list


class _HTTP(urllib.request.HTTPHandler):
    def __init__(self, resolver: Resolver):
        super().__init__()
        self._resolver = resolver

    def http_open(self, req):
        return self.do_open(self._connection, req)

    def _connection(self, host: str, **kwargs) -> http.client.HTTPConnection:
        connection = http.client.HTTPConnection(host, **kwargs)
        connection._create_connection = self._resolver.connect
        return connection


class _HTTPS(urllib.request.HTTPSHandler):
    def __init__(self, resolver: Resolver):
        super().__init__(context=ssl.create_default_context())  # certificates verified, as the app does
        self._resolver = resolver

    def https_open(self, req):
        return self.do_open(self._connection, req, context=self._context)

    def _connection(self, host: str, **kwargs) -> http.client.HTTPSConnection:
        connection = http.client.HTTPSConnection(host, **kwargs)
        connection._create_connection = self._resolver.connect  # SNI and the certificate still name the host
        return connection


class _Redirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlsplit(newurl).scheme.lower() not in ("http", "https"):  # urllib would follow ftp://
            raise _Outcome("down")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def opener(resolver: Resolver) -> urllib.request.OpenerDirector:
    """http(s) only (any other scheme: URLError), no proxies, every connection through the resolver."""
    director = urllib.request.OpenerDirector()
    for handler in (_HTTP(resolver), _HTTPS(resolver), _Redirects(), urllib.request.UnknownHandler(),
                    urllib.request.HTTPDefaultErrorHandler(), urllib.request.HTTPErrorProcessor()):
        director.add_handler(handler)
    return director


@dataclass
class Answer:
    final_url: str
    content_type: str
    body: bytes
    cut: bool  # the body reached its cap


def _lines(body: bytes, cut: bool) -> list[str]:
    """The URI lines of a playlist (a cut body's partial last line dropped)."""
    lines = body.decode("utf-8", "replace").splitlines()
    if cut:
        lines = lines[:-1]
    return [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]


def _join(base: str, uri: str) -> str:
    try:
        return urljoin(base, uri)
    except ValueError:  # an unbalanced "[" in a playlist line
        raise _Outcome("down") from None


def _is_hls(body: bytes) -> bool:
    return body.lstrip(b"\xef\xbb\xbf \t\r\n").startswith(b"#EXTM3U")


def _is_html(answer: Answer) -> bool:
    return answer.content_type.startswith("text/html") or answer.body.lstrip()[:1] == b"<"


def _is_block_page(answer: Answer) -> bool:
    return _is_html(answer) and bool(BLOCK_PAGE.search(answer.body[:BLOCK_PAGE_BYTES]))


def _media_bytes(body: bytes) -> bool:
    """Two MPEG-TS packets, an fMP4 box, ID3-tagged or ADTS audio (sync 0xFFF, layer 00: a UTF-16 BOM, FF FE, is not)."""
    return ((len(body) > 188 and body[0] == 0x47 and body[188] == 0x47) or body[4:8] in FMP4_BOXES
            or body[:3] == b"ID3" or (len(body) > 1 and body[0] == 0xFF and body[1] & 0xF6 == 0xF0))


def _text_shaped(body: bytes) -> bool:
    head = body.lstrip(b"\xef\xbb\xbf \t\r\n")[:TEXT_PROBE].lower()
    return bool(head) and (head.startswith(TEXT_START) or bool(JSON_START.match(head))
                           or all(32 <= byte < 127 or byte in b"\t\r\n" for byte in head))


def _is_text(answer: Answer) -> bool:
    """A page, JSON, playlist or plain-text error rather than media, judged on the bytes: servers label .ts files
    text/vnd.trolltech.linguist."""
    return not _media_bytes(answer.body) and _text_shaped(answer.body)


def _is_media(answer: Answer) -> bool:
    """An audio/video answer: media bytes, or a non-text body under an AV content type (not audio/x-mpegurl)."""
    kind = answer.content_type
    return _media_bytes(answer.body) or (kind.startswith(("video/", "audio/")) and "mpegurl" not in kind
                                         and bool(answer.body) and not _text_shaped(answer.body))


class Prober:
    """probe(row) -> class (module docstring). One instance serves every thread of a run."""

    def __init__(self, resolver: Resolver, socket_timeout: float = SOCKET_TIMEOUT,
                 deadline: float = PROBE_DEADLINE):
        self.resolver = resolver
        self._opener = opener(resolver)
        self._timeout, self.deadline = socket_timeout, deadline

    def __call__(self, row: Row) -> str:
        deadline = time.monotonic() + self.deadline
        headers = {"User-Agent": USER_AGENT, "Accept-Encoding": "identity", **dict(row.headers)}
        try:
            return self._judge(row.url, headers, deadline)
        except _Outcome as outcome:
            return outcome.cls

    def _get(self, url: str, headers: dict[str, str], deadline: float, first: bool, segment: bool = False) -> Answer:
        """One GET; any failure raises _Outcome with its class (gone only for the row's own URL: first)."""
        cap = SEGMENT_BYTES if segment else PLAYLIST_CAP
        try:
            byte_range = {"Range": f"bytes=0-{cap - 1}"} if segment else {}
            request = urllib.request.Request(lists.encoded(url), headers={**headers, **byte_range})
            with self._opener.open(request, timeout=self._timeout) as response:
                chunks, size = [], 0
                while size < cap and (chunk := response.read1(min(1 << 16, cap - size))):
                    size += len(chunk)
                    chunks.append(chunk)
                    if time.monotonic() > deadline:
                        raise _Outcome("down")
                answer = Answer(response.geturl(), response.headers.get("Content-Type", "").lower().strip(),
                                b"".join(chunks), size >= cap)
        except urllib.error.HTTPError as error:
            error.close()
            if error.code in BLOCKED_CODES:
                raise _Outcome("blocked") from None
            raise _Outcome("gone" if first and error.code in GONE_CODES else "down") from None
        except ResolveError as error:
            raise _Outcome("gone" if first and error.cls == "gone" else "down") from None
        except (OSError, http.client.HTTPException, ValueError):  # URLError, timeouts, TLS, resets; bad URLs/headers
            raise _Outcome("down") from None
        if not segment and answer.body[:2] == b"\x1f\x8b":
            try:
                body = lists.gunzip(answer.body, PLAYLIST_CAP)
            except lists.FetchError:
                raise _Outcome("down") from None
            answer.body, answer.cut = body[:PLAYLIST_CAP], answer.cut or len(body) > PLAYLIST_CAP
        return answer

    def _judge(self, url: str, headers: dict[str, str], deadline: float) -> str:
        answer = self._get(url, headers, deadline, first=True)
        if DECOY_URL.search(answer.final_url):
            return "blocked"
        if _is_hls(answer.body):
            return self._judge_hls(answer, headers, deadline)
        if b"<MPD" in answer.body[:4096]:
            return "drm" if b"ContentProtection" in answer.body else "ok"
        if _is_media(answer):
            return "ok"
        return "blocked" if _is_block_page(answer) else "down"

    def _judge_hls(self, answer: Answer, headers: dict[str, str], deadline: float) -> str:
        for hop in range(MASTER_HOPS + 1):
            if HLS_DRM.search(answer.body):
                return "drm"
            if b"#EXT-X-STREAM-INF" not in answer.body:
                break
            variants = _lines(answer.body, answer.cut)
            if not variants or hop == MASTER_HOPS:
                return "down"
            answer = self._get(_join(answer.final_url, variants[0]), headers, deadline, first=False)
            if not _is_hls(answer.body):
                return "blocked" if _is_block_page(answer) else "down"
        segments = _lines(answer.body, answer.cut)
        if not segments:
            return "down"
        segment = self._get(_join(answer.final_url, segments[max(0, len(segments) - 3)]), headers, deadline,
                            first=False, segment=True)
        if not segment.body:
            return "down"
        return "blocked" if _is_text(segment) else "ok"


# --- one run: what to probe, the sweep, the FAST indexes ------------------------------------------------------------

def run_slot(moment: datetime) -> int:
    """This run's place in the week (0-13): the UTC day and whether it is before or after 12:00 (D5)."""
    utc = moment.astimezone(timezone.utc)
    return utc.date().toordinal() % 7 * 2 + utc.hour // 12


def gone_due(rows: Iterable[Row], state: dict[str, Record], now: datetime) -> list[Row]:
    """The gone rows this run re-probes (D3: weekly): those whose key falls in this run's slot of the week, so each is
    probed once a week whatever the ring's lap length (a missed run leaves its rows to the next week)."""
    slot = run_slot(now)
    return sorted((r for r in rows if r.url in state and state[r.url].state == "gone"
                   and int(r.key, 16) % RUNS_A_WEEK == slot), key=lambda r: r.key)


def ring(rows: Iterable[Row], cursor: str | None, state: dict[str, Record]) -> list[Row]:
    """The rows that are not gone, in key order starting after the cursor, wrapping once."""
    ordered = sorted((r for r in rows if r.url not in state or state[r.url].state != "gone"),
                     key=lambda r: (r.key, r.url))
    start = bisect_right([r.key for r in ordered], cursor) if cursor else 0
    return ordered[start:] + ordered[:start]


@dataclass
class Sweep:
    results: dict[str, str]  # url -> class
    taken: int  # rows taken from the input in order (probed, or still waiting at the budget)
    errors: Counter  # unexpected exceptions by type (their rows get no result)


class _Probed(NamedTuple):
    token: int
    cls: str | None  # None: the probe raised an unexpected exception
    error: str | None


class _Looked(NamedTuple):
    host: str


def sweep(rows: list[Row], probe: Callable[[Row], str], stop_at: float, workers: int = WORKERS,
          per_host: int = PER_HOST, deadline: float = PROBE_DEADLINE, resolve: Callable[[str], None] | None = None,
          lookups: int = DNS_LOOKUPS) -> Sweep:
    """Probes rows in order, starting nothing at or after stop_at. A row first waits for its host's lookup (resolve,
    `lookups` daemon threads, one lookup per host; none when resolve is None), then for a slot of its host (at most
    `per_host` in flight); at most `workers` rows are in flight or waiting for a lookup. A row still waiting at stop_at
    is not probed. Each probe runs in a daemon thread; one not done `deadline` seconds after it started counts as down
    and is no longer waited for (a server dripping its handshake or headers holds only that thread). The deadline
    starts after the lookup, so a slow resolver's queue never reads as a dead stream. A probe that raises an
    unexpected exception (a bug) is counted and gives its row no result, so a regression never retires rows."""
    done: queue.SimpleQueue = queue.SimpleQueue()  # _Probed and _Looked messages
    hosts: queue.SimpleQueue = queue.SimpleQueue()
    running: dict[int, tuple[Row, float]] = {}
    looking: dict[str, list[Row]] = {}  # rows waiting for their host's lookup
    resolved: set[str] = set()
    busy: Counter = Counter()
    waiting: dict[str, deque[Row]] = defaultdict(deque)
    results: dict[str, str] = {}
    errors: Counter = Counter()
    tokens = count()
    taken = parked = 0

    def look_up() -> None:
        while (host := hosts.get()) is not None:
            with contextlib.suppress(Exception):  # a bug: the probe meets it again from the cache and sweep counts it
                resolve(host)
            done.put(_Looked(host))

    def attempt(token: int, row: Row) -> None:
        try:
            done.put(_Probed(token, probe(row), None))
        except Exception as error:  # noqa: BLE001  a bug must not stop the run; counted and reported
            done.put(_Probed(token, None, type(error).__name__))

    def start(row: Row) -> None:
        token = next(tokens)
        running[token] = (row, time.monotonic() + deadline)
        busy[row.host] += 1
        threading.Thread(target=attempt, args=(token, row), daemon=True).start()

    def place(row: Row) -> None:
        if busy[row.host] < per_host:
            start(row)
        else:
            waiting[row.host].append(row)

    def finish(token: int, cls: str | None) -> None:
        row, _ = running.pop(token)
        busy[row.host] -= 1
        if cls is not None:
            results[row.url] = cls
        if waiting[row.host] and time.monotonic() < stop_at:
            start(waiting[row.host].popleft())

    if resolve is not None:
        for _ in range(lookups):
            threading.Thread(target=look_up, daemon=True).start()
    while True:
        while taken < len(rows) and len(running) + parked < workers and time.monotonic() < stop_at:
            row = rows[taken]
            taken += 1
            if resolve is None or row.host in resolved:
                place(row)
                continue
            if row.host not in looking:
                looking[row.host] = []
                hosts.put(row.host)
            looking[row.host].append(row)
            parked += 1
        lookups_due = parked and time.monotonic() < stop_at
        if not running and not lookups_due:
            break
        ends = [end for _, end in running.values()] + ([stop_at] if lookups_due else [])
        try:
            message = done.get(timeout=max(0.0, min(ends) - time.monotonic()))
        except queue.Empty:
            now = time.monotonic()
            for token, (_, end) in list(running.items()):
                if end <= now:
                    finish(token, "down")
            continue
        if isinstance(message, _Looked):
            resolved.add(message.host)
            for row in looking.pop(message.host):
                parked -= 1
                if time.monotonic() < stop_at:
                    place(row)
        elif message.token in running:  # else a probe already counted as down at its deadline
            if message.error:
                errors[message.error] += 1
            finish(message.token, message.cls)
    for _ in range(lookups if resolve is not None else 0):
        hosts.put(None)
    return Sweep(results, taken, errors)


def fetch_indexes(fetch: Callable[[str], lists.Fetched] = lists.fetch) -> dict[str, set[str] | None]:
    """service -> provider ids its i.mjh.nz index lists, None when the index cannot be read."""
    def listed(service: str) -> set[str] | None:
        source, _ = lists.FAST_INDEXES[service]
        try:
            index = json.loads(fetch(source).body)
            return {provider_id(row["url"]) for row in lists.fast_rows(service, index)}
        except (lists.FetchError, ValueError, RecursionError):
            return None

    with ThreadPoolExecutor(len(FAST_SERVICES)) as pool:
        return dict(zip(FAST_SERVICES, pool.map(listed, FAST_SERVICES)))


def usable_indexes(indexes: dict[str, set[str] | None], rows: Iterable[Row]) -> dict[str, set[str]]:
    """The indexes that list at least half of the pool's ids of their service (a truncated or emptied index would
    read every row unlisted)."""
    pool_ids: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        pool_ids[row.service].add(row.pid)
    return {service: listed for service, listed in indexes.items()
            if listed is not None and 2 * len(pool_ids[service] & listed) >= len(pool_ids[service])}


def pick_samples(rows: Iterable[Row], indexes: dict[str, set[str]], rng: random.Random) -> list[Row]:
    """Up to SAMPLE listed US rows per usable index (a US runner cannot judge regional rows)."""
    by_service: dict[str, list[Row]] = defaultdict(list)
    for row in sorted(rows, key=lambda r: r.url):
        if row.service in indexes and row.us and row.pid in indexes[row.service]:
            by_service[row.service].append(row)
    return [row for service in sorted(by_service)
            for row in rng.sample(by_service[service], min(SAMPLE, len(by_service[service])))]


def service_result(classes: list[str]) -> str:
    """A service's whole sample: the commonest failing class when most probes fail, blocked when most are blocked,
    else listed (no sample: listed)."""
    failing = [cls for cls in classes if cls in ("down", "gone")]
    if 2 * len(failing) > len(classes):
        return Counter(failing).most_common(1)[0][0]
    if 2 * classes.count("blocked") > len(classes):
        return "blocked"
    return "listed"


def fast_results(rows: Iterable[Row], indexes: dict[str, set[str]], samples: list[Row],
                 probed: dict[str, str]) -> dict[str, str]:
    """url -> class for FAST rows of a usable index whose sample was probed in full (a sample the budget or a bug cut
    short says nothing: its rows keep their records): unlisted, else their service's sample result."""
    planned: dict[str, list[Row]] = defaultdict(list)
    for row in samples:
        planned[row.service].append(row)
    verdicts = {service: service_result([probed[r.url] for r in planned[service]]) for service in indexes
                if all(r.url in probed for r in planned[service])}
    return {row.url: verdicts[row.service] if row.pid in indexes[row.service] else "unlisted"
            for row in rows if row.service in verdicts}


# --- states ------------------------------------------------------------------------------------------------------

def slot_of(moment: datetime) -> int:
    return moment.astimezone(timezone.utc).hour // 3


def _with_slot(slots: str, slot: int) -> str:
    return slots[:slot] + "1" + slots[slot + 1:]


def step(previous: Record | None, cls: str, today: date, slot: int, not247: bool = False) -> Record:
    """The state after one result (Spec 71 D3). since = the day the current streak (ok, failing, blocked) began.
    Success (ok, drm, listed) -> alive. Blocked is never a failure: a row turns blocked when already blocked, when
    new (no working run to protect), or on its second blocked result in a row; otherwise it keeps its state. A failure:
    alive or blocked -> suspect, suspect -> down, down -> gone once it has failed for WINDOWS[0] days with a hard last
    result or WINDOWS[1] days with any (both doubled for a "Not 24/7" row), gone stays. slots marks the UTC 3-hour
    slots seen working since the row was last gone (D5)."""
    empty = "0" * SLOTS
    if previous is None:
        if cls in SUCCESS:
            return Record("alive", today, cls, _with_slot(empty, slot))
        return Record("blocked" if cls == "blocked" else "suspect", today, cls, empty)
    if cls in SUCCESS:
        since = previous.since if previous.state == "alive" else today
        return Record("alive", since, cls, _with_slot(previous.slots, slot))
    if cls == "blocked":
        if previous.state == "blocked" or previous.cls == "blocked":
            return Record("blocked", previous.since if previous.state == "blocked" else today, cls, previous.slots)
        return Record(previous.state, previous.since, cls, previous.slots)
    if previous.state in ("alive", "blocked"):
        return Record("suspect", today, cls, previous.slots)
    if previous.state == "suspect":
        return Record("down", previous.since, cls, previous.slots)
    if previous.state == "down":
        hard_days, any_days = (2 * w for w in WINDOWS) if not247 else WINDOWS
        failing = (today - previous.since).days
        if failing >= any_days or (cls in HARD and failing >= hard_days):
            return Record("gone", previous.since, cls, empty)
    return Record(previous.state, previous.since, cls, previous.slots)


def advance(state: dict[str, Record], results: dict[str, str], rows: dict[str, Row], now: datetime) \
        -> dict[str, Record]:
    """The next state: rows that left the pool or its scope are dropped, rows without a result keep their record."""
    today, slot = now.astimezone(timezone.utc).date(), slot_of(now)
    kept = {url: record for url, record in state.items() if url in rows}
    for url, cls in results.items():
        kept[url] = step(kept.get(url), cls, today, slot, rows[url].not247)
    return kept


# --- state files -------------------------------------------------------------------------------------------------

DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
SLOT_BITS = re.compile(r"[01]{%d}" % SLOTS)
CURSOR = re.compile(r"[0-9a-f]{%d}" % KEY_LENGTH)


def check(state: dict[str, Record], rows: dict[str, Row], today: date) -> None:
    """Refuses (MonitorError) a URL that is not an in-scope pool URL or holds a tab or newline, a state or class
    outside its enum, a since after today, malformed slots."""
    for url, record in state.items():
        if url not in rows or any(c in url for c in "\t\r\n"):
            raise MonitorError("a state row's URL is not an in-scope pool URL")
        if (record.state not in STATES or record.cls not in CLASSES or record.since > today
                or not SLOT_BITS.fullmatch(record.slots)):
            raise MonitorError("a state row holds a value outside its enum or range")


def read_state(repo: Path) -> dict[str, Record]:
    path = repo / STATE_FILE
    if not path.exists():
        return {}
    lines = path.read_text(encoding="utf-8").split("\n")
    if lines[0].split("\t") != STATE_COLUMNS:
        raise MonitorError("state.tsv has unexpected columns")
    state: dict[str, Record] = {}
    for line in filter(None, lines[1:]):
        cells = line.split("\t")
        if len(cells) != len(STATE_COLUMNS) or not DATE.fullmatch(cells[2]):
            raise MonitorError("state.tsv has a malformed row")
        try:
            state[cells[0]] = Record(cells[1], date.fromisoformat(cells[2]), cells[3], cells[4])
        except ValueError as error:
            raise MonitorError("state.tsv has a malformed date") from error
    return state


def read_cursor(repo: Path) -> str | None:
    path = repo / CURSOR_FILE
    if not path.exists():
        return None
    cursor = path.read_text(encoding="ascii").strip()
    if not CURSOR.fullmatch(cursor):
        raise MonitorError("monitor/cursor is malformed")
    return cursor


def _replace(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    os.replace(temporary, path)


def write_state(repo: Path, state: dict[str, Record], cursor: str | None, rows: dict[str, Row], today: date) -> None:
    """Checks everything, then writes state.tsv (sorted by URL) and the cursor."""
    check(state, rows, today)
    if cursor is not None and not CURSOR.fullmatch(cursor):
        raise MonitorError("cursor is malformed")
    lines = ["\t".join(STATE_COLUMNS)] + ["\t".join((url, r.state, r.since.isoformat(), r.cls, r.slots))
                                          for url, r in sorted(state.items())]
    _replace(repo / STATE_FILE, "\n".join(lines) + "\n")
    if cursor is not None:
        _replace(repo / CURSOR_FILE, cursor + "\n")


# --- the run ------------------------------------------------------------------------------------------------------

@dataclass
class Report:
    rows: int
    fast: int
    gone_due: int
    due: int
    taken: int
    sampled: int
    indexes: dict[str, str]
    results: Counter
    states: Counter
    changed: int
    errors: Counter
    seconds: float


def run(repo: Path, now: datetime, stop_at: float, prober: Prober, workers: int = WORKERS,
        lookups: int = DNS_LOOKUPS, fetch: Callable[[str], lists.Fetched] = lists.fetch) -> Report:
    """One monitor run over the repo (module docstring); raises MonitorError before writing anything it refuses."""
    started = time.monotonic()
    rows = load_rows(pool_paths(repo))
    state, cursor = read_state(repo), read_cursor(repo)
    fast_rows = [row for row in rows.values() if row.service]
    others = [row for row in rows.values() if not row.service]
    indexes = usable_indexes(fetch_indexes(fetch), fast_rows)
    samples = pick_samples(fast_rows, indexes, random.Random(now.isoformat()))
    gone = gone_due(others, state, now)
    head = samples + gone  # probed first, outside the ring and its cursor
    due = ring(others, cursor, state)
    done = sweep(head + due, prober, stop_at, workers, deadline=prober.deadline, resolve=prober.resolver.warm,
                 lookups=lookups)
    results = {row.url: done.results[row.url] for row in gone + due if row.url in done.results}
    results.update(fast_results(fast_rows, indexes, samples, done.results))
    taken = max(0, done.taken - len(head))  # ring rows taken: sweep takes rows in order, head first
    new_state = advance(state, results, rows, now)
    write_state(repo, new_state, due[taken - 1].key if taken else cursor, rows, now.astimezone(timezone.utc).date())
    return Report(rows=len(rows), fast=len(fast_rows), gone_due=len(gone), due=len(due), taken=taken,
                  sampled=len(samples), indexes={s: ("used" if s in indexes else "not used") for s in FAST_SERVICES},
                  results=Counter(results.values()), states=Counter(r.state for r in new_state.values()),
                  changed=sum(1 for url, r in new_state.items() if state.get(url) != r), errors=done.errors,
                  seconds=round(time.monotonic() - started, 1))


def main(argv: list[str] | None = None) -> int:
    started = time.monotonic()
    parser = argparse.ArgumentParser(description="Probe a channel repo's pool and update monitor/state.tsv.")
    parser.add_argument("repo", type=Path)
    parser.add_argument("--budget", type=float, required=True, help="seconds from start after which no probe starts")
    parser.add_argument("--workers", type=int, default=WORKERS)
    parser.add_argument("--lookups", type=int, default=DNS_LOOKUPS, help="DNS lookups at once")
    args = parser.parse_args(argv)
    try:
        report = run(args.repo, datetime.now(timezone.utc), started + args.budget,
                     Prober(Resolver(lookups=args.lookups)), args.workers, args.lookups)
    except MonitorError as error:
        print(f"monitor: {error}; nothing written", file=sys.stderr)
        return 1
    print(f"in scope {report.rows} (FAST {report.fast}); gone due {report.gone_due}; ring due {report.due}, taken "
          f"{report.taken}; FAST sample {report.sampled}; indexes {report.indexes}; {report.seconds} s")
    print(f"results {dict(report.results)}; states {dict(report.states)}; rows changed {report.changed}"
          + (f"; probe errors {dict(report.errors)}" if report.errors else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
