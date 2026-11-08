"""Unit tests for the channel monitor (Spec 71 M1.2): probe classes against a local HTTP server, the resolver, the
sweep, the FAST indexes, states, scope and the state files. Hermetic: test hosts resolve to 127.0.0.1 through a fake
lookup.
Run: python3 -m unittest discover -s harvest
"""
import dataclasses
import gzip
import json
import random
import socket
import tempfile
import threading
import time
import unittest
import urllib.request
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from unittest import mock
from collections import Counter
from datetime import date, datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import build_pool
import lists
import monitor
from monitor import MonitorError, Record, Row, step

PLUTO_ID = "5ca671f215a62078d2ec0abf"
STATIC_LIST = "https://raw.githubusercontent.com/someone/lists/main/all.m3u"  # a static source: nothing minted
TS = (b"\x47" + b"\x00" * 187) * 4
MEDIA = b"#EXTM3U\n#EXT-X-TARGETDURATION:6\n" + b"".join(b"#EXTINF:6,\nseg%d.ts\n" % i for i in range(1, 5))
HLS = "application/vnd.apple.mpegurl"


def master(uri: str, extra: bytes = b"") -> bytes:
    return b"#EXTM3U\n" + extra + b"#EXT-X-STREAM-INF:BANDWIDTH=1\n" + uri.encode() + b"\n"


def media(segment: str, extra: bytes = b"") -> bytes:
    return b"#EXTM3U\n#EXT-X-TARGETDURATION:6\n" + extra + b"#EXTINF:6,\n" + segment.encode() + b"\n"


# path -> (status, content type, body, extra headers)
ROUTES = {
    "/master.m3u8": (200, HLS, master("low/media.m3u8"), {}),
    "/low/media.m3u8": (200, HLS, MEDIA, {}),
    "/low/seg2.ts": (200, "video/mp2t", TS, {}),
    "/media.m3u8": (200, HLS, MEDIA, {}),
    "/seg2.ts": (200, "video/mp2t", TS, {}),
    "/nested.m3u8": (200, HLS, master("master.m3u8"), {}),
    "/loop.m3u8": (200, HLS, master("loop.m3u8"), {}),
    "/fairplay.m3u8": (200, HLS, media("seg2.ts", b'#EXT-X-KEY:METHOD=SAMPLE-AES,URI="skd://k",'
                                                  b'KEYFORMAT="com.apple.streamingkeydelivery"\n'), {}),
    "/widevine.m3u8": (200, HLS, master("low/media.m3u8", b'#EXT-X-SESSION-KEY:METHOD=SAMPLE-AES-CTR,URI="data:x",'
                                       b'KEYFORMAT="urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed"\n'), {}),
    "/aes.m3u8": (200, HLS, media("seg2.ts", b'#EXT-X-KEY:METHOD=AES-128,URI="key.bin"\n'), {}),
    "/seg403.m3u8": (200, HLS, media("forbidden"), {}),
    "/seg404.m3u8": (200, HLS, media("missing"), {}),
    "/variant404.m3u8": (200, HLS, master("missing"), {}),
    "/htmlseg.m3u8": (200, HLS, media("page"), {}),
    "/empty.m3u8": (200, HLS, b"#EXTM3U\n#EXT-X-TARGETDURATION:6\n", {}),
    "/rtmp.m3u8": (200, HLS, master("rtmp://example.org/live"), {}),
    "/missing": (404, "text/html", b"<html>not found</html>", {}),
    "/removed": (410, "text/plain", b"", {}),
    "/forbidden": (403, "text/html", b"<html>no</html>", {}),
    "/unauthorized": (401, "text/plain", b"", {}),
    "/error": (500, "text/plain", b"", {}),
    "/bad": (400, "text/plain", b"", {}),
    "/throttled": (429, "text/plain", b"", {}),
    "/dash.mpd": (200, "application/dash+xml", b'<?xml version="1.0"?><MPD><Period><AdaptationSet><ContentProtection '
                  b'schemeIdUri="urn:mpeg:dash:mp4protection:2011"/></AdaptationSet></Period></MPD>', {}),
    "/clear.mpd": (200, "application/dash+xml", b'<?xml version="1.0"?><MPD><Period/></MPD>', {}),
    "/video": (200, "video/mp2t", TS, {}),
    "/tsbody": (200, "application/octet-stream", TS, {}),
    "/short": (200, "text/plain", b"Gone", {}),
    "/videohtml": (200, "video/mp4", b"<html>error</html>", {}),
    "/page": (200, "text/html", b"<html><body>Welcome</body></html>", {}),
    "/akamai": (200, "text/html", b"<HTML><HEAD><TITLE>Access Denied</TITLE></HEAD><BODY><H1>Access Denied</H1>"
                b"You don't have permission.<P>Reference&#32;&#35;18&#46;5c</BODY></HTML>", {}),
    "/country": (200, "text/html", b"<p>Sorry, we block access from your country.</p>", {}),
    "/redirect": (302, "text/plain", b"", {"Location": "/master.m3u8"}),
    "/redirect-ftp": (302, "text/plain", b"", {"Location": "ftp://example.org/live.m3u8"}),
    "/redirect-gone": (302, "text/plain", b"", {"Location": "/missing"}),
    "/decoy": (302, "text/plain", b"", {"Location": "/video_no_available.mp4"}),
    "/video_no_available.mp4": (200, "video/mp4", b"\x00\x00\x00\x18ftypmp42", {}),
    "/gz.m3u8": (200, HLS, gzip.compress(MEDIA.replace(b"seg", b"/seg")), {}),
    "/badgz.m3u8": (200, HLS, b"\x1f\x8bnot gzip", {}),
    "/htmlvariant.m3u8": (200, HLS, master("page"), {}),
    "/blockvariant.m3u8": (200, HLS, master("akamai"), {}),
    "/textseg.m3u8": (200, HLS, media("textts"), {}),
    "/textts": (200, "text/vnd.trolltech.linguist", TS, {}),
    "/aesseg.m3u8": (200, HLS, media("cipher"), {}),
    "/cipher": (200, "video/mp2t", b"{\x8a\x13" + bytes(range(256)) * 4, {}),  # AES-128 ciphertext: random bytes
    "/utf16": (200, "text/html", "<html>gone</html>".encode("utf-16"), {}),
    "/aestext.m3u8": (200, HLS, media("ciphertext"), {}),
    "/ciphertext": (200, "text/vnd.trolltech.linguist", b"\x8a\x13" + bytes(range(256)) * 4, {}),
    "/plainseg.m3u8": (200, HLS, media("plain"), {}),
    "/plain": (200, "application/octet-stream", b"Forbidden: this content is not available here", {}),
    "/jsonseg.m3u8": (200, HLS, media("json"), {}),
    "/json": (200, "video/mp2t", b'\xef\xbb\xbf{\n  "error": "geo"}', {}),
    "/blankseg.m3u8": (200, HLS, media("blank"), {}),
    "/blank": (200, "video/mp2t", b"\r\n \r\n", {}),
    "/nonascii.m3u8": (200, HLS, media("nonascii"), {}),
    "/nonascii": (200, "video/mp2t", "<p>Acceso denegado \u2013 contenido no disponible</p>".encode(), {}),
    "/tagseg.m3u8": (200, HLS, media("tag"), {}),
    "/tag": (200, "video/mp2t", "<title>\u0414\u043e\u0441\u0442\u0443\u043f \u0437\u0430\u043f\u0440\u0435"
                                "\u0449\u0435\u043d\u00a0\x01".encode(), {}),
    "/jsonarr.m3u8": (200, HLS, media("jsonarr"), {}),
    "/jsonarr": (200, "video/mp2t", b'[ {"error": "\xd0\x94\x01"}]', {}),
    # Cut at the cap inside its last line: dropping that line makes seg2.ts (ok) the segment three from the end; keeping
    # it would pick "missing" (down).
    "/cut.m3u8": (200, HLS, media("seg2.ts") + b"#EXTINF:6,\nmissing\n#EXTINF:6,\nseg2.ts\n#EXTINF:6,\n"
                  + b"x" * monitor.PLAYLIST_CAP, {}),
}


class Handler(BaseHTTPRequestHandler):
    seen: list = []

    def do_GET(self):  # noqa: N802  (http.server's name)
        Handler.seen.append((self.path, self.headers.get("Range"), self.headers.get("User-Agent")))
        if self.path == "/slow":
            time.sleep(2)
        if self.path == "/referer":
            ok = self.headers.get("Referer") == "https://site.example/"
            status, kind, body, extra = (200, "video/mp2t", TS, {}) if ok else (403, "text/plain", b"", {})
        elif self.path in ("/redirect-nx", "/redirect-lan"):
            target = f"http://{self.path[10:]}.test:{self.server.server_port}/video"
            status, kind, body, extra = 302, "text/plain", b"", {"Location": target}
        elif self.path == "/nxvariant.m3u8":
            status, kind, body, extra = 200, HLS, master(f"http://nx.test:{self.server.server_port}/media.m3u8"), {}
        else:
            status, kind, body, extra = ROUTES.get(self.path, (404, "text/plain", b"", {}))
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        for name, value in extra.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class FakeLookup:
    """host -> addresses; an int answers socket.gaierror with that code; a list of answers is used in turn."""

    def __init__(self, table=None):
        self.table, self.calls = table or {}, Counter()

    def __call__(self, host):
        self.calls[host] += 1
        answer = self.table.get(host, ["127.0.0.1"])
        if isinstance(answer, tuple):
            answer = answer[min(self.calls[host], len(answer)) - 1]
        if isinstance(answer, int):
            raise socket.gaierror(answer, "fake")
        return answer


def row(url: str, **fields) -> Row:
    return Row(url=url, host=fields.pop("host", (urlsplit(url).hostname or "").lower()), key=monitor.ring_key(url),
               headers=fields.pop("headers", ()), not247=fields.pop("not247", False), us=fields.pop("us", False),
               service=fields.pop("service", None), pid=fields.pop("pid", None))


class ServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.server.daemon_threads = True
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.port = cls.server.server_port

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        Handler.seen.clear()
        self.lookup = FakeLookup({"nx.test": socket.EAI_NONAME, "nodata.test": socket.EAI_NODATA,
                                  "again.test": socket.EAI_AGAIN, "flaky.test": (socket.EAI_AGAIN, ["127.0.0.1"]),
                                  "lan.test": ["10.0.0.1"]})
        self.prober = monitor.Prober(monitor.Resolver(self.lookup, public=lambda address: True, retry_pause=0))

    def url(self, path: str, host: str = "good.test") -> str:
        return f"http://{host}:{self.port}{path}"

    def probe(self, path: str, host: str = "good.test", **fields) -> str:
        return self.prober(row(self.url(path, host), **fields))


class ProbeClassTest(ServerTest):
    def test_master_media_segment_chain_reads_ok_with_a_range_on_the_segment_three_from_the_end(self):
        self.assertEqual(self.probe("/master.m3u8"), "ok")
        fetched = {path: byte_range for path, byte_range, _ in Handler.seen}
        self.assertEqual(list(fetched), ["/master.m3u8", "/low/media.m3u8", "/low/seg2.ts"])
        self.assertEqual(fetched["/low/seg2.ts"], "bytes=0-65535")

    def test_media_playlist_and_master_nested_once_read_ok(self):
        self.assertEqual(self.probe("/media.m3u8"), "ok")
        self.assertEqual(self.probe("/nested.m3u8"), "ok")

    def test_a_master_still_pointing_at_a_master_after_two_hops_is_down(self):
        self.assertEqual(self.probe("/loop.m3u8"), "down")

    def test_sample_aes_and_drm_key_formats_are_drm_but_aes_128_is_not(self):
        self.assertEqual(self.probe("/fairplay.m3u8"), "drm")
        self.assertEqual(self.probe("/widevine.m3u8"), "drm")
        self.assertEqual(self.probe("/aes.m3u8"), "ok")

    def test_http_codes_of_the_row_url(self):
        expected = {"/missing": "gone", "/removed": "gone", "/forbidden": "blocked", "/unauthorized": "blocked",
                    "/error": "down", "/bad": "down", "/throttled": "down"}
        self.assertEqual({path: self.probe(path) for path in expected}, expected)

    def test_later_steps_never_read_gone(self):
        self.assertEqual(self.probe("/seg403.m3u8"), "blocked")
        self.assertEqual(self.probe("/seg404.m3u8"), "down")
        self.assertEqual(self.probe("/variant404.m3u8"), "down")
        self.assertEqual(self.probe("/empty.m3u8"), "down")
        self.assertEqual(self.probe("/rtmp.m3u8"), "down")

    def test_a_text_segment_is_blocked_but_media_bytes_win_over_a_text_type(self):
        self.assertEqual(self.probe("/htmlseg.m3u8"), "blocked")
        self.assertEqual(self.probe("/textseg.m3u8"), "ok")
        self.assertEqual(self.probe("/aesseg.m3u8"), "ok")
        self.assertEqual(self.probe("/aestext.m3u8"), "ok")  # ciphertext under a text type: bytes decide
        self.assertEqual(self.probe("/plainseg.m3u8"), "blocked")
        self.assertEqual(self.probe("/jsonseg.m3u8"), "blocked")  # a BOM and pretty-printed JSON
        self.assertEqual(self.probe("/nonascii.m3u8"), "blocked")  # printable UTF-8, no known opening
        self.assertEqual(self.probe("/tagseg.m3u8"), "blocked")  # a known opening, then a control byte
        self.assertEqual(self.probe("/jsonarr.m3u8"), "blocked")  # a JSON array, then a control byte
        self.assertEqual(self.probe("/blankseg.m3u8"), "down")  # only whitespace: no media

    def test_a_utf16_page_is_not_audio(self):
        self.assertEqual(self.probe("/utf16"), "down")

    def test_an_html_variant_is_down_unless_it_names_a_block(self):
        self.assertEqual(self.probe("/htmlvariant.m3u8"), "down")
        self.assertEqual(self.probe("/blockvariant.m3u8"), "blocked")

    def test_a_cut_playlist_drops_its_partial_last_line(self):
        self.assertEqual(self.probe("/cut.m3u8"), "ok")

    def test_dash_and_av_answers_are_judged_on_the_first_answer(self):
        self.assertEqual(self.probe("/dash.mpd"), "drm")
        self.assertEqual(self.probe("/clear.mpd"), "ok")
        self.assertEqual(self.probe("/video"), "ok")
        self.assertEqual(self.probe("/tsbody"), "ok")

    def test_short_text_and_html_under_a_video_type_are_not_media(self):
        self.assertEqual(self.probe("/short"), "down")
        self.assertEqual(self.probe("/videohtml"), "down")

    def test_a_page_is_down_unless_it_names_a_block(self):
        self.assertEqual(self.probe("/page"), "down")
        self.assertEqual(self.probe("/akamai"), "blocked")
        self.assertEqual(self.probe("/country"), "blocked")

    def test_redirects(self):
        self.assertEqual(self.probe("/redirect"), "ok")
        self.assertEqual(self.probe("/redirect-gone"), "gone")  # the row's own answer, after its redirects
        self.assertEqual(self.probe("/redirect-ftp"), "down")
        self.assertEqual(self.probe("/decoy"), "blocked")

    def test_row_headers_are_sent_else_the_monitor_user_agent(self):
        self.assertEqual(self.probe("/referer"), "blocked")
        self.assertEqual(Handler.seen[-1][2], monitor.USER_AGENT)
        self.assertEqual(self.probe("/referer", headers=(("Referer", "https://site.example/"),)), "ok")

    def test_a_gzip_playlist_is_read_and_a_broken_one_is_down(self):
        self.assertEqual(self.probe("/gz.m3u8"), "ok")
        self.assertEqual(self.probe("/badgz.m3u8"), "down")

    def test_a_probe_past_its_deadline_is_down(self):
        prober = monitor.Prober(monitor.Resolver(self.lookup, public=lambda a: True), deadline=0.5)
        started = time.monotonic()
        result = monitor.sweep([row(self.url("/slow"))], prober, time.monotonic() + 10, deadline=0.5)
        self.assertEqual(result.results, {self.url("/slow"): "down"})
        self.assertLess(time.monotonic() - started, 1.8)


class ResolverTest(ServerTest):
    def test_no_such_name_is_gone_for_the_row_and_its_redirects_only(self):
        self.assertEqual(self.probe("/media.m3u8", host="nx.test"), "gone")
        self.assertEqual(self.probe("/redirect-nx"), "gone")
        self.assertEqual(self.probe("/nxvariant.m3u8"), "down")

    def test_a_redirect_to_a_non_public_address_is_refused_before_connecting(self):
        self.prober = monitor.Prober(monitor.Resolver(self.lookup, public=lambda address: address != "10.0.0.1"))
        self.assertEqual(self.probe("/redirect-lan"), "down")
        self.assertEqual([path for path, _, _ in Handler.seen], ["/redirect-lan"])

    def test_https_connections_go_through_the_resolver(self):
        resolver = monitor.Resolver(FakeLookup())
        handler = next(h for h in monitor.opener(resolver).handlers if isinstance(h, urllib.request.HTTPSHandler))
        connection = handler._connection("good.test", timeout=1, context=handler._context)
        self.assertEqual(connection._create_connection, resolver.connect)

    def test_a_lookup_bug_reaches_every_asker_and_gives_no_result(self):
        def lookup(host):
            raise KeyError(host)

        resolver = monitor.Resolver(lookup, public=lambda address: True)
        with self.assertRaises(KeyError):
            resolver.addresses("bug.test")  # the first asker: the bug itself
        with self.assertRaises(RuntimeError):
            resolver.addresses("bug.test")  # later askers: a fresh exception, never the shared one
        prober = monitor.Prober(monitor.Resolver(lookup, public=lambda address: True))
        done = monitor.sweep([row(self.url("/video", "bug.test"))], prober, time.monotonic() + 10,
                             resolve=prober.resolver.warm)
        self.assertEqual((done.results, done.errors), ({}, Counter({"RuntimeError": 1})))

    def test_concurrent_askers_share_one_lookup(self):
        lookup = FakeLookup()
        resolver = monitor.Resolver(lambda host: time.sleep(0.3) or lookup(host), public=lambda address: True)
        threads = [threading.Thread(target=resolver.addresses, args=("good.test",)) for _ in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(lookup.calls["good.test"], 1)

    def test_no_data_is_down_it_rose_with_resolver_load(self):
        self.assertEqual(self.probe("/media.m3u8", host="nodata.test"), "down")

    def test_a_temporary_lookup_failure_is_retried_once_then_down(self):
        self.assertEqual(self.probe("/media.m3u8", host="flaky.test"), "ok")
        self.assertEqual(self.probe("/media.m3u8", host="again.test"), "down")
        self.assertEqual(self.lookup.calls["again.test"], 2)

    def test_a_probe_lookup_never_queues_behind_the_lookup_stage(self):
        resolver = monitor.Resolver(lambda host: time.sleep(1 if host == "stage.test" else 0) or ["127.0.0.1"],
                                    public=lambda address: True, lookups=1)
        threading.Thread(target=resolver.warm, args=("stage.test",), daemon=True).start()
        time.sleep(0.1)
        started = time.monotonic()
        resolver.addresses("redirect.test")
        self.assertLess(time.monotonic() - started, 0.5)

    def test_lookup_outcomes_are_counted_once_per_host_by_fixed_text(self):
        self.prober = monitor.Prober(monitor.Resolver(self.lookup, public=lambda address: address != "10.0.0.1",
                                                      retry_pause=0))
        for host in ("good.test", "good.test", "nx.test", "nodata.test", "again.test", "lan.test"):
            self.probe("/media.m3u8", host=host)
        self.assertEqual(self.prober.resolver.outcomes,
                         Counter({"ok": 1, "no such name": 1, "lookup failed (EAI_NODATA)": 1,
                                  "lookup failed (EAI_AGAIN)": 1, "not a public address": 1}))

    def test_each_host_is_looked_up_once_per_run(self):
        for path in ("/master.m3u8", "/media.m3u8", "/video"):
            self.probe(path)
        self.assertEqual(self.lookup.calls["good.test"], 1)

    def test_a_non_public_address_is_refused(self):
        prober = monitor.Prober(monitor.Resolver(FakeLookup()))  # the real public check: 127.0.0.1 is not public
        self.assertEqual(prober(row(self.url("/video"))), "down")
        self.assertEqual(Handler.seen, [])
        refused = monitor.Resolver(FakeLookup({"mixed.test": ["8.8.8.8", "10.0.0.1"]}))
        with self.assertRaises(monitor.ResolveError):
            refused.addresses("mixed.test")


class SweepTest(unittest.TestCase):
    def test_per_host_cap_and_queued_rows_drain(self):
        lock, active, peak = threading.Lock(), Counter(), Counter()

        def probe(r):
            with lock:
                for key in (r.host, "all"):
                    active[key] += 1
                    peak[key] = max(peak[key], active[key])
            time.sleep(0.03)
            with lock:
                for key in (r.host, "all"):
                    active[key] -= 1
            return "ok"

        rows = [row(f"http://{h}.test/{i}") for h in "abc" for i in range(8)]
        done = monitor.sweep(rows, probe, time.monotonic() + 10, workers=6, per_host=4)
        self.assertEqual(len(done.results), 24)
        self.assertLessEqual(max(peak[f"{h}.test"] for h in "abc"), 4)
        self.assertLessEqual(peak["all"], 6)
        self.assertEqual(done.taken, 24)

    def test_nothing_starts_after_the_budget_and_queued_rows_are_missed(self):
        self.assertEqual(monitor.sweep([row("http://a.test/1")], lambda r: "ok", time.monotonic() - 1).taken, 0)
        rows = [row(f"http://a.test/{i}") for i in range(3)] + [row("http://b.test/1")]
        done = monitor.sweep(rows, lambda r: time.sleep(1.5) or "ok", time.monotonic() + 0.5, per_host=1)
        self.assertEqual(set(done.results), {"http://a.test/0", "http://b.test/1"})
        self.assertEqual(done.taken, 4)

    def test_the_deadline_starts_after_the_host_lookup(self):
        looked = Counter()

        def resolve(host):
            looked[host] += 1
            time.sleep(0.4)

        rows = [row(f"http://a.test/{i}") for i in range(3)]
        done = monitor.sweep(rows, lambda r: "ok", time.monotonic() + 10, deadline=0.2, resolve=resolve, lookups=2)
        self.assertEqual(set(done.results.values()), {"ok"})
        self.assertEqual(looked, Counter({"a.test": 1}))

    def test_rows_still_waiting_for_a_lookup_at_the_budget_are_not_probed(self):
        rows = [row("http://slow.test/1"), row("http://fast.test/1")]
        done = monitor.sweep(rows, lambda r: "ok", time.monotonic() + 0.5, lookups=2,
                             resolve=lambda host: time.sleep(2 if host == "slow.test" else 0))
        self.assertEqual(done.results, {"http://fast.test/1": "ok"})
        self.assertEqual(done.taken, 2)

    def test_an_unexpected_probe_error_is_counted_and_gives_no_result(self):
        def probe(r):
            raise RuntimeError("bug")

        done = monitor.sweep([row("http://a.test/1")], probe, time.monotonic() + 10)
        self.assertEqual(done.results, {})
        self.assertEqual(done.errors, Counter({"RuntimeError": 1}))


class RingTest(unittest.TestCase):
    def test_starts_after_the_cursor_and_wraps(self):
        rows = sorted((row(f"http://a.test/{i}") for i in range(5)), key=lambda r: r.key)
        self.assertEqual(monitor.ring(rows, None, {}), rows)
        self.assertEqual(monitor.ring(rows, rows[1].key, {}), rows[2:] + rows[:2])

    def test_run_slot_counts_two_runs_a_day(self):
        morning = datetime(2026, 11, 8, 3, 17, tzinfo=timezone.utc)
        slots = [monitor.run_slot(morning + timedelta(hours=12 * n)) for n in range(14)]
        self.assertEqual(sorted(slots), list(range(14)))

    def test_gone_rows_leave_the_ring_and_are_due_once_a_week_whatever_the_lap(self):
        gone, live = row("http://a.test/gone"), row("http://a.test/live")
        state = {gone.url: Record("gone", date(2026, 1, 1), "gone", "0" * 8)}
        self.assertEqual(monitor.ring([gone, live], None, state), [live])
        runs = [datetime(2026, 11, 1, 3, 17, tzinfo=timezone.utc) + timedelta(hours=12 * n) for n in range(28)]
        due = [run for run in runs if monitor.gone_due([gone, live], state, run)]
        self.assertEqual(len(due), 2)  # one run in each of the two weeks
        self.assertEqual(due[1] - due[0], timedelta(days=7))


class FastTest(unittest.TestCase):
    def fast(self, ident: str, us: bool = True) -> Row:
        return row(f"https://jmp2.uk/plu-{ident}.m3u8", us=us, service="pluto", pid=f"pluto:{ident}")

    def test_an_index_listing_under_half_the_pool_ids_or_unreadable_is_not_used(self):
        rows = [self.fast(f"{i:024x}") for i in range(4)]
        ids = {r.pid for r in rows}
        self.assertEqual(set(monitor.usable_indexes({"pluto": set(list(ids)[:2]), "roku": None}, rows)), {"pluto"})
        self.assertEqual(monitor.usable_indexes({"pluto": set(list(ids)[:1])}, rows), {})

    def test_samples_are_listed_us_rows_only(self):
        rows = [self.fast(f"{i:024x}") for i in range(30)] + [self.fast("f" * 24, us=False)]
        listed = {"pluto": {r.pid for r in rows[1:]}}
        picked = monitor.pick_samples(rows, listed, random.Random(1))
        self.assertEqual(len(picked), monitor.SAMPLE)
        self.assertTrue(all(r.us and r.pid in listed["pluto"] for r in picked))
        self.assertEqual(monitor.pick_samples([self.fast("a" * 24, us=False)], {"pluto": {"pluto:" + "a" * 24}},
                                              random.Random(1)), [])

    def test_service_result_needs_most_probes_failing_or_blocked(self):
        self.assertEqual(monitor.service_result(["down"] * 11 + ["ok"] * 9), "down")
        self.assertEqual(monitor.service_result(["gone"] * 6 + ["down"] * 5 + ["ok"] * 9), "gone")
        self.assertEqual(monitor.service_result(["down"] * 10 + ["ok"] * 10), "listed")
        self.assertEqual(monitor.service_result(["blocked"] * 11 + ["ok"] * 9), "blocked")
        self.assertEqual(monitor.service_result([]), "listed")

    def test_unlisted_rows_and_the_sample_result(self):
        listed, dropped = self.fast("a" * 24), self.fast("b" * 24)
        results = monitor.fast_results([listed, dropped], {"pluto": {listed.pid}}, [listed], {listed.url: "down"})
        self.assertEqual(results, {listed.url: "down", dropped.url: "unlisted"})

    def test_a_sample_cut_short_gives_its_service_no_result(self):
        rows = [self.fast(f"{i:024x}") for i in range(3)]
        listed = {"pluto": {r.pid for r in rows}}
        self.assertEqual(monitor.fast_results(rows, listed, rows, {rows[0].url: "down"}), {})
        self.assertEqual(set(monitor.fast_results(rows, listed, [], {}).values()), {"listed"})  # no US rows

    def test_fetch_indexes_reads_ids_and_tolerates_failures(self):
        def fetch(url):
            if "PlutoTV" in url:
                body = json.dumps({"regions": {"us": {"channels": {PLUTO_ID: {"name": "News"}}}}}).encode()
                return lists.Fetched(url, url, body)
            if "Roku" in url:
                return lists.Fetched(url, url, b"[]")  # a changed shape
            raise lists.FetchError("down")

        self.assertEqual(monitor.fetch_indexes(fetch),
                         {"pluto": {f"pluto:{PLUTO_ID}"}, "samsung": None, "roku": None, "plex": None})


class StepTest(unittest.TestCase):
    today = date(2026, 11, 8)

    def rec(self, state: str, days_ago: int = 0, cls: str = "down", slots: str = "00000000") -> Record:
        return Record(state, self.today - timedelta(days=days_ago), cls, slots)

    def test_new_rows(self):
        self.assertEqual(step(None, "ok", self.today, 2), Record("alive", self.today, "ok", "00100000"))
        self.assertEqual(step(None, "down", self.today, 2).state, "suspect")
        self.assertEqual(step(None, "blocked", self.today, 2).state, "blocked")

    def test_failures_climb_suspect_down_gone(self):
        suspect = step(self.rec("alive", 3, "ok", "10000000"), "down", self.today, 0)
        self.assertEqual(suspect, Record("suspect", self.today, "down", "10000000"))
        self.assertEqual(step(self.rec("suspect", 1), "down", self.today, 0), self.rec("down", 1))
        self.assertEqual(step(self.rec("down", 13, slots="11000000"), "gone", self.today, 0).state, "down")
        self.assertEqual(step(self.rec("down", 14, slots="11000000"), "gone", self.today, 0),
                         Record("gone", self.today - timedelta(days=14), "gone", "00000000"))
        self.assertEqual(step(self.rec("down", 29), "down", self.today, 0).state, "down")
        self.assertEqual(step(self.rec("down", 30), "down", self.today, 0).state, "gone")
        self.assertEqual(step(self.rec("down", 14), "unlisted", self.today, 0).state, "gone")
        self.assertEqual(step(self.rec("gone", 40), "down", self.today, 0).state, "gone")

    def test_not_24_7_rows_wait_twice_as_long(self):
        self.assertEqual(step(self.rec("down", 27), "gone", self.today, 0, not247=True).state, "down")
        self.assertEqual(step(self.rec("down", 28), "gone", self.today, 0, not247=True).state, "gone")
        self.assertEqual(step(self.rec("down", 59), "down", self.today, 0, not247=True).state, "down")

    def test_blocked_needs_two_in_a_row_and_is_never_a_failure(self):
        once = step(self.rec("alive", 5, "ok"), "blocked", self.today, 0)
        self.assertEqual(once, self.rec("alive", 5, "blocked"))
        self.assertEqual(step(once, "blocked", self.today, 0), self.rec("blocked", 0, "blocked"))
        self.assertEqual(step(self.rec("down", 10), "blocked", self.today, 0), self.rec("down", 10, "blocked"))
        self.assertEqual(step(self.rec("blocked", 4, "blocked"), "blocked", self.today, 0),
                         self.rec("blocked", 4, "blocked"))
        self.assertEqual(step(self.rec("blocked", 4, "blocked"), "down", self.today, 0), self.rec("suspect", 0))

    def test_any_success_is_alive_and_marks_its_slot(self):
        self.assertEqual(step(self.rec("alive", 9, "ok", "10000000"), "ok", self.today, 7),
                         self.rec("alive", 9, "ok", "10000001"))
        self.assertEqual(step(self.rec("gone", 40, "gone"), "drm", self.today, 3),
                         self.rec("alive", 0, "drm", "00010000"))
        self.assertEqual(step(self.rec("blocked", 2, "blocked"), "listed", self.today, 0).state, "alive")

    def test_advance_drops_rows_that_left_the_pool_and_keeps_unprobed_ones(self):
        kept, probed = row("http://a.test/kept"), row("http://a.test/probed")
        state = {kept.url: self.rec("down", 3), probed.url: self.rec("alive", 3, "ok"), "http://a.test/left":
                 self.rec("alive")}
        now = datetime(2026, 11, 8, 15, 17, tzinfo=timezone.utc)
        new = monitor.advance(state, {probed.url: "ok"}, {kept.url: kept, probed.url: probed}, now)
        self.assertEqual(new, {kept.url: self.rec("down", 3), probed.url: self.rec("alive", 3, "ok", "00000100")})


class ScopeTest(unittest.TestCase):
    def pool_row(self, url: str, **cells) -> dict:
        return {**{c: "-" for c in build_pool.POOL_COLUMNS}, "url": url, "reason": "nsfw", "seen_in": "lists:1",
                "kind": "stream", "source_page": STATIC_LIST, **cells}

    def test_credentials_minted_and_other_schemes_are_never_probed(self):
        for url, cells in [("http://panel.example:8080/live/u1/p1/1.ts", {}),
                           ("http://panel.example:8080/u1/p1/1", {"reason": "listed:xtreamiptv.xyz"}),
                           ("https://cdn.example/live.m3u8", {"headers": '{"Referer":"https://s.example/?token=a"}'}),
                           ("https://cdn.example/live.m3u8", {"headers": '{"Referer":"https://s.example/?token=a"}',
                                                             "seen_in": "iptv-org", "reason": "iptv-org-url"}),
                           ("https://cdn.example/live.m3u8?token=abc", {}),
                           ("https://cdn.example/live.m3u8", {"reason": "minted"}),
                           ("https://cdn.example/live.m3u8", {"reason": "credential"}),
                           ("https://cdn.example/live.m3u8", {"headers": '{"Referer":"https://u:p@site.example/"}'}),
                           ("https://cdn.example/live.m3u8", {"notes": "IP-bound session URL"}),
                           ("rtmp://cdn.example/live", {"reason": "unreviewed-host"}),
                           ("https://www.youtube.com/watch?v=x", {"reason": "unreviewed-host"})]:
            self.assertIsNone(monitor.scoped(self.pool_row(url, **cells)), (url, cells))

    def test_faults_behind_an_nsfw_or_drm_reason_still_skip(self):
        listed_list = "https://raw.githubusercontent.com/zokerpunk/tv/main/all.m3u"
        self.assertIsNone(monitor.scoped(self.pool_row("https://cdn.example/a.m3u8", source_page=listed_list)))
        self.assertIsNone(monitor.scoped(self.pool_row("https://cdn.example/a.m3u8", reason="drm",
                                                       source_page="https://broadcaster.example/api/live")))
        self.assertIsNotNone(monitor.scoped(self.pool_row("https://cdn.example/a.m3u8", reason="drm",
                                                          notes="license_url (DRM)")))  # D2 probes a drm fault

    def test_a_token_url_iptv_org_lists_is_probed(self):
        found = monitor.scoped(self.pool_row("https://cdn.example/live.m3u8?token=abc", reason="iptv-org-url",
                                             seen_in="iptv-org,lists:2"))
        self.assertEqual(found.host, "cdn.example")

    def test_row_fields(self):
        found = monitor.scoped(self.pool_row(
            f"https://jmp2.uk/plu-{PLUTO_ID}.m3u8", reason="fast-host", country="US;CA", notes="Not 24/7",
            headers='{"Referer":"https://site.example/","Cookie":"s=1","User-Agent":"bad\\r\\nX: y"}'))
        self.assertEqual((found.service, found.pid, found.us, found.not247), ("pluto", f"pluto:{PLUTO_ID}", True, True))
        self.assertEqual(found.headers, (("Referer", "https://site.example/"),))
        latin = monitor.scoped(self.pool_row("https://cdn.example/a.m3u8", reason="fast-host",
                                             headers='{"User-Agent":"Caf\u00e9/1","Origin":"https://\u4e2d.example"}'))
        self.assertEqual(latin.headers, (("User-Agent", "Caf\u00e9/1"),))  # http.client sends Latin-1 only
        relay = monitor.scoped(self.pool_row("https://i.mjh.nz/.r/news.m3u8", reason="fast-host"))
        self.assertIsNone(relay.service)


class FilesTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)

    def tearDown(self):
        self.directory.cleanup()

    def test_pool_paths_by_repo_kind(self):
        public, private = self.root / "public", self.root / "private"
        (public / "harvest").mkdir(parents=True)
        private.mkdir()
        self.assertEqual(monitor.pool_paths(public), [public / "pool" / "streams.tsv"])
        self.assertEqual(monitor.pool_paths(private), [private / "pool" / "private.tsv", private / "pool" / "nsfw.tsv"])
        with self.assertRaises(MonitorError):
            monitor.pool_paths(public / "pool")  # inside the public checkout
        (public / "pool").mkdir()
        (public / "pool" / "nsfw.tsv").write_text("x")
        with self.assertRaises(MonitorError):
            monitor.pool_paths(public)
        with redirect_stderr(StringIO()) as err:
            self.assertEqual(monitor.main([str(public), "--budget", "1"]), 1)
        self.assertIn("nothing written", err.getvalue())
        self.assertFalse((public / "monitor").exists())

    def test_state_round_trip_and_refusals(self):
        a = row("http://a.test/1")
        record = Record("alive", date(2026, 11, 8), "ok", "00000001")
        monitor.write_state(self.root, {a.url: record}, a.key, {a.url: a}, date(2026, 11, 8))
        self.assertEqual(monitor.read_state(self.root), {a.url: record})
        self.assertEqual(monitor.read_cursor(self.root), a.key)
        written = (self.root / monitor.STATE_FILE).read_bytes()
        for state, rows in [({"http://b.test/x": record}, {a.url: a}),
                            ({a.url: dataclasses.replace(record, state="dead")}, {a.url: a}),
                            ({a.url: dataclasses.replace(record, cls="maybe")}, {a.url: a}),
                            ({a.url: dataclasses.replace(record, since=date(2026, 11, 9))}, {a.url: a}),
                            ({a.url: dataclasses.replace(record, slots="0001")}, {a.url: a})]:
            with self.assertRaises(MonitorError):
                monitor.write_state(self.root, state, a.key, rows, date(2026, 11, 8))
        self.assertEqual((self.root / monitor.STATE_FILE).read_bytes(), written)

    def test_malformed_files_are_refused(self):
        (self.root / "monitor").mkdir()
        (self.root / monitor.CURSOR_FILE).write_text("not-a-cursor\n")
        with self.assertRaises(MonitorError):
            monitor.read_cursor(self.root)
        (self.root / monitor.STATE_FILE).write_text("url\tstate\n")
        with self.assertRaises(MonitorError):
            monitor.read_state(self.root)
        (self.root / monitor.STATE_FILE).write_text("url\tstate\tsince\tclass\tslots\nhttp://a\talive\t20261108\tok\t"
                                                    "00000000\n")
        with self.assertRaises(MonitorError):
            monitor.read_state(self.root)


class RunTest(ServerTest):
    def test_two_runs_write_states_and_move_the_cursor(self):
        with tempfile.TemporaryDirectory() as name:
            repo = Path(name)
            (repo / "harvest").mkdir()
            urls = [self.url(p) for p in ("/master.m3u8", "/missing", "/forbidden")]
            fast = f"https://jmp2.uk/plu-{PLUTO_ID}.m3u8"
            rows = [{**{c: "-" for c in build_pool.POOL_COLUMNS}, "url": u, "reason": "iptv-org-url",
                     "seen_in": "iptv-org", "country": "US" if u == fast else "-"} for u in urls + [fast]]
            self.lookup.table["jmp2.uk"] = socket.EAI_NONAME  # the US sample row: its service reads gone
            (repo / "pool").mkdir()
            (repo / "pool" / "streams.tsv").write_text(build_pool.tsv(rows, build_pool.POOL_COLUMNS))
            index = {"regions": {"ca": {"channels": {PLUTO_ID: {"name": "News"}}}}}

            def fetch(url, listing=index):
                if "PlutoTV" in url:
                    return lists.Fetched(url, url, json.dumps(listing).encode())
                raise lists.FetchError("down")

            first = datetime(2026, 11, 8, 3, 17, tzinfo=timezone.utc)
            report = monitor.run(repo, first, time.monotonic() + 10, self.prober, fetch=fetch)
            state = monitor.read_state(repo)
            self.assertEqual({u: (r.state, r.cls) for u, r in state.items()},
                             {urls[0]: ("alive", "ok"), urls[1]: ("suspect", "gone"), urls[2]: ("blocked", "blocked"),
                              fast: ("suspect", "gone")})
            self.assertEqual(state[urls[0]].slots, "01000000")
            self.assertEqual((report.taken, report.due, report.sampled), (3, 3, 1))
            self.assertEqual(report.lookups, Counter({"ok": 1, "no such name": 1}))  # good.test, the sample's host
            self.assertEqual(monitor.read_cursor(repo), max(monitor.ring_key(u) for u in urls))

            report = monitor.run(repo, first + timedelta(hours=12), time.monotonic() + 10, self.prober,
                                 fetch=lambda url: fetch(url, {"regions": {"ca": {"channels": {}}}}))
            state = monitor.read_state(repo)
            self.assertEqual(state[urls[1]].state, "down")
            # an index listing none of the pool's ids is not used: the FAST row keeps its record
            self.assertEqual(state[fast], Record("suspect", first.date(), "gone", "00000000"))
            cursor = monitor.read_cursor(repo)

            # a gone row is re-probed only in its run of the week, before the ring, and never moves the cursor
            gone_url = urls[0]
            state[gone_url] = Record("gone", first.date() - timedelta(days=40), "gone", "00000000")
            monitor.write_state(repo, state, cursor, monitor.load_rows(monitor.pool_paths(repo)), first.date())
            key = int(monitor.ring_key(gone_url), 16) % monitor.RUNS_A_WEEK
            runs = [first + timedelta(hours=12 * n) for n in range(2, 30)]
            due = [r for r in runs if monitor.run_slot(r) == key][1]  # the second week's: other runs precede it
            other = next(r for r in runs if monitor.run_slot(r) != key)
            monitor.run(repo, other, time.monotonic() + 10, self.prober, fetch=fetch)
            self.assertEqual(monitor.read_state(repo)[gone_url].state, "gone")
            report = monitor.run(repo, due, time.monotonic() + 10, self.prober, fetch=fetch)
            self.assertEqual((report.gone_due, report.due, report.taken), (1, 2, 2))
            self.assertEqual(monitor.read_state(repo)[gone_url].state, "alive")
            self.assertEqual(monitor.read_cursor(repo), max(monitor.ring_key(u) for u in urls[1:]))
            state, cursor = monitor.read_state(repo), monitor.read_cursor(repo)

            # the budget already spent: nothing probed, the sample cut short, nothing changes
            monitor.run(repo, due + timedelta(hours=12), time.monotonic() - 1, self.prober, fetch=fetch)
            self.assertEqual(monitor.read_state(repo), state)
            self.assertEqual(monitor.read_cursor(repo), cursor)


class MainTest(unittest.TestCase):
    def test_the_run_prints_aggregates_with_lookups_cpu_and_memory(self):
        report = monitor.Report(rows=3, fast=1, gone_due=0, due=2, taken=2, sampled=1, indexes={}, results=Counter(),
                                states=Counter(), changed=0, errors=Counter(), lookups=Counter({"ok": 2}),
                                seconds=1.0)
        with tempfile.TemporaryDirectory() as name, mock.patch.object(monitor, "run", return_value=report), \
                redirect_stdout(StringIO()) as out:
            self.assertEqual(monitor.main([name, "--budget", "1"]), 0)
        self.assertRegex(out.getvalue(), r"\nlookups \{'ok': 2\}; CPU \d+\.\d s; max RSS \d+ MB\n$")


if __name__ == "__main__":
    unittest.main()
