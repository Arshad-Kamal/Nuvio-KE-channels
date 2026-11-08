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
        elif self.path.startswith("/redirect-nx"):
            target = f"http://nx.test:{self.server.server_port}/"
            status, kind, body, extra = 302, "text/plain", b"", {"Location": target}
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

    def test_a_text_segment_is_blocked(self):
        self.assertEqual(self.probe("/htmlseg.m3u8"), "blocked")

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

    def test_a_gzip_playlist_is_read(self):
        self.assertEqual(self.probe("/gz.m3u8"), "ok")

    def test_a_probe_past_its_deadline_is_down(self):
        prober = monitor.Prober(monitor.Resolver(self.lookup, public=lambda a: True), deadline=0.5)
        started = time.monotonic()
        result = monitor.sweep([row(self.url("/slow"))], prober, time.monotonic() + 10, deadline=0.5)
        self.assertEqual(result.results, {self.url("/slow"): "down"})
        self.assertLess(time.monotonic() - started, 1.5)


class ResolverTest(ServerTest):
    def test_no_such_name_is_gone_for_the_row_and_its_redirects_only(self):
        self.assertEqual(self.probe("/media.m3u8", host="nx.test"), "gone")
        self.assertEqual(self.probe("/redirect-nx"), "gone")

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
                active[r.host] += 1
                peak[r.host] = max(peak[r.host], active[r.host])
            time.sleep(0.03)
            with lock:
                active[r.host] -= 1
            return "ok"

        rows = [row(f"http://a.test/{i}") for i in range(12)] + [row(f"http://b.test/{i}") for i in range(4)]
        done = monitor.sweep(rows, probe, time.monotonic() + 10, workers=8, per_host=4)
        self.assertEqual(len(done.results), 16)
        self.assertLessEqual(peak["a.test"], 4)
        self.assertEqual(done.taken, 16)

    def test_nothing_starts_after_the_budget_and_queued_rows_are_missed(self):
        self.assertEqual(monitor.sweep([row("http://a.test/1")], lambda r: "ok", time.monotonic() - 1).taken, 0)
        rows = [row(f"http://a.test/{i}") for i in range(3)] + [row("http://b.test/1")]
        done = monitor.sweep(rows, lambda r: time.sleep(0.3) or "ok", time.monotonic() + 0.1, per_host=1)
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
        done = monitor.sweep(rows, lambda r: "ok", time.monotonic() + 0.3, lookups=2,
                             resolve=lambda host: time.sleep(1 if host == "slow.test" else 0))
        self.assertEqual(done.results, {"http://fast.test/1": "ok"})
        self.assertEqual(done.taken, 2)

    def test_an_unexpected_probe_error_counts_as_down(self):
        def probe(r):
            raise RuntimeError("bug")

        done = monitor.sweep([row("http://a.test/1")], probe, time.monotonic() + 10)
        self.assertEqual(done.results, {"http://a.test/1": "down"})
        self.assertEqual(done.errors, Counter({"RuntimeError": 1}))


class RingTest(unittest.TestCase):
    def test_starts_after_the_cursor_and_wraps(self):
        rows = sorted((row(f"http://a.test/{i}") for i in range(5)), key=lambda r: r.key)
        self.assertEqual(monitor.ring(rows, None, {}, date(2026, 11, 8)), rows)
        self.assertEqual(monitor.ring(rows, rows[1].key, {}, date(2026, 11, 8)), rows[2:] + rows[:2])

    def test_gone_rows_only_on_their_weekday(self):
        gone = row("http://a.test/gone")
        state = {gone.url: Record("gone", date(2026, 1, 1), "gone", "0" * 8)}
        days = [date(2026, 11, 1) + timedelta(days=n) for n in range(7)]
        probed = [day for day in days if monitor.ring([gone], None, state, day)]
        self.assertEqual(len(probed), 1)
        self.assertEqual(int(gone.key, 16) % 7, probed[0].toordinal() % 7)


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
        results = monitor.fast_results([listed, dropped], {"pluto": {listed.pid}}, {"pluto": ["down"] * 3})
        self.assertEqual(results, {listed.url: "down", dropped.url: "unlisted"})

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
                **cells}

    def test_credentials_minted_and_other_schemes_are_never_probed(self):
        for url, cells in [("http://panel.example:8080/live/u1/p1/1.ts", {}),
                           ("https://cdn.example/live.m3u8?token=abc", {}),
                           ("https://cdn.example/live.m3u8", {"reason": "minted"}),
                           ("https://cdn.example/live.m3u8", {"reason": "credential"}),
                           ("https://cdn.example/live.m3u8", {"headers": '{"Referer":"https://u:p@site.example/"}'}),
                           ("https://cdn.example/live.m3u8", {"notes": "IP-bound session URL"}),
                           ("rtmp://cdn.example/live", {"reason": "unreviewed-host"}),
                           ("https://www.youtube.com/watch?v=x", {"reason": "unreviewed-host"})]:
            self.assertIsNone(monitor.scoped(self.pool_row(url, **cells)), (url, cells))

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
        relay = monitor.scoped(self.pool_row("https://i.mjh.nz/.r/news.m3u8", reason="fast-host"))
        self.assertIsNone(relay.service)


class FilesTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)

    def tearDown(self):
        self.directory.cleanup()

    def test_pool_files_by_repo_kind(self):
        public, private = self.root / "public", self.root / "private"
        (public / "harvest").mkdir(parents=True)
        private.mkdir()
        self.assertEqual(monitor.pool_files(public), [public / "pool" / "streams.tsv"])
        self.assertEqual(monitor.pool_files(private), [private / "pool" / "private.tsv", private / "pool" / "nsfw.tsv"])
        with self.assertRaises(MonitorError):
            monitor.pool_files(public / "pool")  # inside the public checkout
        (public / "pool").mkdir()
        (public / "pool" / "nsfw.tsv").write_text("x")
        with self.assertRaises(MonitorError):
            monitor.pool_files(public)

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
                     "seen_in": "iptv-org"} for u in urls + [fast]]
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
                              fast: ("alive", "listed")})
            self.assertEqual(state[urls[0]].slots, "01000000")
            self.assertEqual((report.taken, report.due, report.sampled), (3, 3, 0))
            self.assertEqual(monitor.read_cursor(repo), max(monitor.ring_key(u) for u in urls))

            report = monitor.run(repo, first + timedelta(hours=12), time.monotonic() + 10, self.prober,
                                 fetch=lambda url: fetch(url, {"regions": {"ca": {"channels": {}}}}))
            state = monitor.read_state(repo)
            self.assertEqual(state[urls[1]].state, "down")
            # an index listing none of the pool's ids is not used: the FAST row keeps its record
            self.assertEqual(state[fast], Record("alive", first.date(), "listed", "01000000"))


if __name__ == "__main__":
    unittest.main()
