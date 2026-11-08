"""Unit tests for the list parsers, the channel join and the pool builder (Spec 60 H1b).
Run: python3 -m unittest discover -s harvest
"""
import base64
import contextlib
import io
import json
import socket
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

import build_pool
import egress
import extract_research
import lists
import rules
from allowlist import Allowlist, parse_reviewed
from channels import Channels, fast_id, name_key, provider_id, spread_nsfw
from extract_research import COLUMNS, OUT_COLUMNS
from rules import verdict, vouches

PLUTO_ID = "5ca671f215a62078d2ec0abf"
SOURCE = "https://raw.githubusercontent.com/someone/lists/main/all.m3u"


def research(url, kind="list-endpoint", fmt="m3u", reason="unreviewed-host", bucket="private"):
    values = dict.fromkeys(COLUMNS, "-")
    values.update(url=url, kind=kind, format=fmt, reason=reason, seen_in="r/01", _bucket=bucket)
    return values


class M3uTest(unittest.TestCase):
    def parse(self, text):
        return list(lists.parse_m3u(text, SOURCE))

    def test_attributes_name_and_headers(self):
        rows = self.parse('#EXTM3U\n#EXTINF:-1 tvg-id="CNN.us@East" tvg-country="US" group-title="News, World",'
                          'CNN, East\n#EXTVLCOPT:http-referrer=https://cnn.example/\n'
                          '#EXTVLCOPT:http-user-agent=Mozilla/5.0\nhttps://cdn.example/cnn.m3u8\n')
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual((row["name"], row["country"], row["category"], row["tvg_id"], row["source_page"]),
                         ("CNN, East", "US", "News, World", "CNN.us@East", SOURCE))
        self.assertEqual(json.loads(row["headers"]), {"Referer": "https://cnn.example/", "User-Agent": "Mozilla/5.0"})

    def test_kodi_drm_pipe_headers_and_trailing_text(self):
        rows = self.parse("#EXTINF:-1,A\n#KODIPROP:inputstream.adaptive.license_type=clearkey\n"
                          "https://a.example/a.mpd\n#EXTINF:-1,B\nhttps://b.example/b.mpd|Referer=https%3A%2F%2Fb.tv/&Cookie=sid%3D1\n"
                          "#EXTINF:-1,C\nhttps://c.example/c.m3u8 some text\n")
        self.assertEqual([r["url"] for r in rows], ["https://a.example/a.mpd", "https://b.example/b.mpd",
                                                     "https://c.example/c.m3u8"])
        self.assertEqual(rows[0]["notes"], "KODIPROP license (DRM)")
        self.assertEqual(rows[1]["headers"], '{"Referer":"https://b.tv/"}')  # Cookie dropped
        self.assertEqual(rows[2]["notes"], "-")

    def test_untrusted_cells_stay_single_line_and_capped(self):
        rows = self.parse("#EXTINF:-1," + "x\ty" * 200 + "\nhttps://a.example/a.m3u8\n")
        self.assertNotIn("\t", rows[0]["name"])
        self.assertLessEqual(len(rows[0]["name"]), lists.MAX_NAME)

    def test_a_second_url_gets_no_name_tvg_id_or_directives_and_images_are_skipped(self):
        rows = self.parse('#EXTINF:-1 tvg-id="A.us",A\n#EXTVLCOPT:http-user-agent=UA\nhttps://a.example/a.m3u8\n'
                          "https://b.example/b.m3u8\n#EXTINF:-1,Logo\nhttps://img.example/logo.png\n")
        self.assertEqual([(r["url"], r["name"], r["tvg_id"], r["headers"]) for r in rows],
                         [("https://a.example/a.m3u8", "A", "A.us", '{"User-Agent":"UA"}'),
                          ("https://b.example/b.m3u8", "-", "", "-")])  # run 15: backups of unrelated channels


class JsonListTest(unittest.TestCase):
    def test_stream_keys_are_read_and_artwork_is_not(self):
        data = {"channels": [{"name": "A", "url": "https://a.example/a.m3u8", "logo": "https://a.example/a.png",
                              "art": "https://a.example/a"},
                             {"title": "B", "streams": [{"src": "https://b.example/b.m3u8"},
                                                        {"file": "https://b.example/poster.jpg"}]}]}
        rows = list(lists.parse_json_list(data, SOURCE))
        self.assertEqual([(r["name"], r["url"]) for r in rows],
                         [("A", "https://a.example/a.m3u8"), ("B", "https://b.example/b.m3u8")])

    def test_a_url_holding_whitespace_is_skipped(self):
        data = [{"name": "T", "url": "https://a.example/a\tb.m3u8"}, {"name": "U", "url": "https://a.example/a\u2028.m3u8"},
                {"name": "V", "url": " https://a.example/v.m3u8 "}]
        self.assertEqual([r["url"] for r in lists.parse_json_list(data, SOURCE)], ["https://a.example/v.m3u8"])

    def test_deep_nesting_does_not_recurse(self):
        data = {"url": "https://a.example/a.m3u8"}
        for _ in range(5000):
            data = {"adult": data}
        started = time.monotonic()
        self.assertEqual(len(list(lists.parse_json_list(data, SOURCE))), 1)
        self.assertLess(time.monotonic() - started, 5)  # str() of each nested flag value took 19 s here (round 7)

    def test_bodies_that_are_not_lists(self):
        for body in (b"#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=1\nhttps://a.example/1.m3u8\n", b"<html></html>",
                     b"{not json", b'{"version": "1.0", "name": "addon"}'):
            self.assertEqual(lists.parse_list(lists.Fetched(SOURCE, SOURCE, body)), ("not-a-list", []), body)


class ListTargetTest(unittest.TestCase):
    def test_classes(self):
        cases = {
            "https://iptv-org.github.io/iptv/index.m3u": (None, "skip:iptv-org"),
            "https://raw.githubusercontent.com/iptv-org/iptv/master/streams/us.m3u": (None, "skip:iptv-org"),
            "https://github.com/o/r/blob/main/a/list.m3u?raw=true":
                ("https://raw.githubusercontent.com/o/r/main/a/list.m3u", "static"),
            "https://github.com/o/r/raw/main/list.m3u": ("https://raw.githubusercontent.com/o/r/main/list.m3u", "static"),
            "https://gist.github.com/o/0123abcd": ("https://gist.github.com/o/0123abcd/raw", "static"),
            "https://github.com/o/r": (None, "skip:page"),
            "https://api.github.com/repos/o/r/contents/streams": (None, "skip:page"),
            "https://i.mjh.nz/PlutoTV/all.xml.gz": (None, "skip:epg"),
            "https://i.mjh.nz/PlutoTV/.channels.json": (None, "skip:fast-index"),
            "https://i.mjh.nz/.r/dw-news.m3u8": (None, "skip:redirector"),
            "https://jmp2.uk/plu-x.m3u8": (None, "skip:redirector"),
            "https://jmp2.uk/plu-{channelUUID}.m3u8": (None, "skip:template"),
            "https://i.mjh.nz/au/all/raw-tv.m3u8": ("https://i.mjh.nz/au/all/raw-tv.m3u8", "static"),
            "https://someone.github.io/x/streams.json": ("https://someone.github.io/x/streams.json", "static"),
            "https://www.lists.example/fast.m3u": ("https://www.lists.example/fast.m3u", "other-host"),
            "https://api.broadcaster.example/v1/channels": (None, "skip:api"),
            "rtmp://x.example/live": (None, "skip:not-http"),
        }
        for url, expected in cases.items():
            self.assertEqual(lists.list_target(research(url, fmt="-")), expected, url)


def resolving_to(address):
    return mock.patch.object(socket, "getaddrinfo", return_value=[(socket.AF_INET, 0, 0, "", (address, 0))])


class FetchTest(unittest.TestCase):
    def test_non_public_addresses_and_schemes_are_refused(self):
        for address in ("127.0.0.1", "192.168.1.20", "10.0.0.1", "169.254.169.254", "::1"):
            with resolving_to(address), self.assertRaises(lists.FetchError, msg=address):
                lists.fetch("https://lists.example/a.m3u")
        with self.assertRaises(lists.FetchError):
            lists.fetch("file:///etc/passwd")

    def test_a_redirect_to_a_private_address_is_refused(self):
        handler = lists._PublicRedirects()
        with resolving_to("192.168.1.1"), self.assertRaises(lists.FetchError):
            handler.redirect_request(None, None, 302, "Found", {}, "http://router.example/")
        with self.assertRaises(lists.FetchError):
            handler.redirect_request(None, None, 302, "Found", {}, "ftp://files.example/a.m3u")


class FastRowsTest(unittest.TestCase):
    def test_each_service(self):
        pluto = {"regions": {"us": {"channels": {PLUTO_ID: {"name": "P", "group": "News"}}},
                             "ca": {"channels": {PLUTO_ID: {"name": "P", "group": "News"}}}}}
        samsung = {"slug": "stvp-{id}", "regions": {"gb": {"channels": {
            "GB1": {"name": "S"}, "GB2": {"name": "D", "license_url": "https://lic.example/widevine"}}}}}
        roku = {"channels": {"f9c0d48b540a55dcb98b04d2cc8abf25": {"name": "R", "groups": ["News"]}}}
        plex = {"channels": {"6a16-66635f": {"name": "X", "regions": ["us", "mx"]}, "../evil": {"name": "E"}}}
        rows = {s: list(lists.fast_rows(s, i)) for s, i in
                (("pluto", pluto), ("samsung", samsung), ("roku", roku), ("plex", plex))}
        self.assertEqual([(r["url"], r["country"]) for r in rows["pluto"]],
                         [(f"https://jmp2.uk/plu-{PLUTO_ID}.m3u8", "US;CA")])
        self.assertEqual([(r["url"], r["notes"]) for r in rows["samsung"]],
                         [("https://jmp2.uk/stvp-GB1", "-"), ("https://jmp2.uk/stvp-GB2", "license_url (DRM)")])
        self.assertEqual([(r["url"], r["country"], r["category"]) for r in rows["roku"]],
                         [("https://jmp2.uk/rok-f9c0d48b540a55dcb98b04d2cc8abf25.m3u8", "US", "News")])
        self.assertEqual([r["url"] for r in rows["plex"]], ["https://jmp2.uk/plex-6a16-66635f.m3u8"])

    def test_a_changed_shape_raises(self):
        with self.assertRaises(ValueError):
            list(lists.fast_rows("pluto", {"channels": []}))


class IptvOrgRowsTest(unittest.TestCase):
    def test_fields(self):
        streams = [{"channel": "CNN.us", "feed": "East", "title": "CNN", "url": "https://cnn.example/a.m3u8",
                    "referrer": None, "user_agent": "#EXTVLCOPT:http-user-agent=Mozilla/5.0",
                    "quality": "720p", "labels": ["Geo-blocked"]}, {"url": None}, "junk"]
        rows = list(lists.iptv_org_rows(streams))
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["tvg_id"], rows[0]["headers"], rows[0]["geo_hint"], rows[0]["notes"]),
                         ("CNN.us@East", '{"User-Agent":"Mozilla/5.0"}', "geo-blocked", "Geo-blocked; quality 720p"))


ALLOW = Allowlist(["https://iptv.example/a.m3u8", "https://cdn.example.org/b.m3u8"], parse_reviewed(""), vouches)


def copy(url, source=SOURCE, **cells):
    values = dict.fromkeys(COLUMNS, "-")
    values.update(name="Channel", url=url, kind="stream", source_page=source)
    values.update(cells)
    return values


def merged(*copies):
    return rules.merge((c, f"o{n}", verdict(c, ALLOW)) for n, c in enumerate(copies))


def b64(text):
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")


class EncodedCredentialTest(unittest.TestCase):
    def test_a_session_wrapped_in_base64_is_a_credential_even_when_iptv_org_lists_it(self):
        claims = b64(json.dumps({"user_phone": "+000000000000", "exp": 1}))
        inner = f"http://198.51.100.5:7000/ch1/mono.m3u8?live=1&id=1&token=eyJhbGciOiJIUzI1NiJ9.{claims}.sig"
        wrapped = f"https://iptv.example/playlist.m3u8?source={b64(inner)}"
        allow = Allowlist([wrapped], parse_reviewed(""), vouches)
        self.assertEqual(verdict(copy(wrapped), allow), rules.Verdict("private", "credential"))
        secret = f"https://iptv.example/p.m3u8?source={b64('http://198.51.100.5/a.m3u8?ip=1&secret=x')}"
        self.assertEqual(rules.url_rejection(secret), ("private", "credential"))
        encoded = "https://iptv.example/p.m3u8?u=http%3A%2F%2Fa%3Ab%40198.51.100.5%2Flive.m3u8"
        self.assertEqual(rules.url_rejection(encoded), ("private", "credential"))

    def test_a_jwt_without_personal_claims_is_not_a_credential(self):
        token = "eyJhbGciOiJIUzI1NiJ9." + b64(json.dumps({"exp": 1, "sip": "", "path": "/live"})) + ".sig"
        self.assertIsNone(rules.url_rejection(f"https://iptv.example/a.m3u8?hdnts={token}"))


class MergeRankTest(unittest.TestCase):
    def test_a_pirate_list_copy_does_not_veto_a_clean_copy(self):
        url = "https://iptv.example/a.m3u8"
        for order in ((copy(url, "https://raw.githubusercontent.com/zokerpunk/x/main/a.m3u"), copy(url)),
                      (copy(url), copy(url, "https://raw.githubusercontent.com/zokerpunk/x/main/a.m3u"))):
            row = merged(*order)[url]
            self.assertEqual((row["_bucket"], row["reason"], row["source_page"]), ("public", "iptv-org-url", SOURCE))

    def test_the_public_copy_publishes_its_own_cells(self):
        url = "https://cdn.example.org/live/c.m3u8"  # an iptv-org host, not an iptv-org URL
        row = merged(copy(url, "https://broadcaster.example/watch", notes="seen live"),
                     copy(url, notes="player uses ?token=abc"), copy(url, notes="clean"))[url]
        self.assertEqual((row["_bucket"], row["notes"], row["seen_in"]), ("public", "clean", "o0,o1,o2"))
        self.assertEqual(merged(copy(url, name="A"), copy(url, name="-"), copy(url, name="B"))[url]["_names"], ["A", "B"])

    def test_a_verdict_about_the_stream_wins_over_a_public_copy(self):
        url = "https://iptv.example/a.m3u8"
        row = merged(copy(url), copy(url, name="A (Widevine)"))[url]
        self.assertEqual((row["_bucket"], row["reason"]), ("private", "drm"))
        row = merged(copy(url), copy(url, name="Erotica"))[url]
        self.assertEqual((row["_bucket"], row["reason"]), ("nsfw", "nsfw"))

    def test_a_copy_failing_both_kinds_reports_the_stream_reason(self):
        found = verdict(copy("https://cdn.example.org/a.mpd", "https://raw.githubusercontent.com/zokerpunk/x/a.m3u",
                             notes="Widevine"), ALLOW)
        self.assertEqual(found, rules.Verdict("private", "drm", False))

    def test_only_copy_only_copies_stay_private(self):
        url = "https://cdn.example.org/live/d.m3u8"
        row = merged(copy(url, "https://raw.githubusercontent.com/zokerpunk/x/a.m3u"))[url]
        self.assertEqual((row["_bucket"], row["reason"]), ("private", "listed:zokerpunk"))


class FakeResponse:
    def __init__(self, chunks):
        self.chunks = list(chunks)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def geturl(self):
        return SOURCE

    def read1(self, size):
        return self.chunks.pop(0) if self.chunks else b""


class ListsTest(unittest.TestCase):
    """Parsers, list targets and fetches (lists.py) on hostile or malformed input."""

    def test_drm_before_extinf_json_drm_keys_kodi_suffix_and_pages(self):
        rows = list(lists.parse_m3u("#KODIPROP:inputstream.adaptive.license_type=clearkey\n#EXTINF:-1,A\n"
                                    "https://a.example/a.mpd\n", SOURCE))
        self.assertEqual(rows[0]["notes"], "KODIPROP license (DRM)")
        data = [{"name": "D", "url": "https://d.example/d.mpd", "license_key": "k"},
                {"name": "K", "url": "https://k.example/k.m3u8|Referer=https://k.tv/&Cookie=s"},
                {"name": "P", "url": "https://cdn.jwplayer.com/players/abc.html"}, {"name": "R", "url": "https://tv.example/"},
                {"name": "Rai", "url": "https://mediapolis.rai.it/relinker/relinkerServlet.htm?cont=2606803"}]
        rows = list(lists.parse_json_list(data, SOURCE))
        self.assertEqual([(r["url"], r["notes"], r["headers"]) for r in rows],
                         [("https://d.example/d.mpd", "license key (DRM)", "-"),
                          ("https://k.example/k.m3u8", "-", '{"Referer":"https://k.tv/"}'),
                          ("https://mediapolis.rai.it/relinker/relinkerServlet.htm?cont=2606803", "-", "-")])

    def test_media_playlists_epg_names_and_credential_lists(self):
        media = b"#EXTM3U\n#EXT-X-TARGETDURATION:6\n#EXTINF:6.0,\nhttps://cdn.example/seg1.ts\n"
        self.assertEqual(lists.parse_list(lists.Fetched(SOURCE, SOURCE, media)), ("not-a-list", []))
        epg_named = "https://raw.githubusercontent.com/o/r/main/Italy_No_EPG.m3u"
        self.assertEqual(lists.list_target(research(epg_named, fmt="-")), (epg_named, "static"))
        for panel in ("http://panel.example:8080/get.php?username=u&password=p&type=m3u",
                      "http://xxx-panel.example:8080/get.php?username=u&password=p&type=m3u"):  # NSFW-named too
            self.assertEqual(lists.list_target(research(panel)), (None, "skip:credential"), panel)

    def test_samsung_index_shapes(self):
        for index in ({"slug": "stvp-{id}\tx", "regions": {}}, {"slug": "stvp", "regions": {}}, ["not", "a", "dict"]):
            with self.assertRaises(ValueError):
                list(lists.fast_rows("samsung", index))

    def test_corrupt_gzip_and_a_trickling_server_fail_one_fetch(self):
        with resolving_to("93.184.216.34"), mock.patch.object(lists._OPENER, "open",
                                                              return_value=FakeResponse([b"\x1f\x8b\x08\x00junk"])):
            with self.assertRaises(lists.FetchError):
                lists.fetch("https://lists.example/a.m3u")
        clock = iter(range(0, 10_000, 100))
        with resolving_to("93.184.216.34"), mock.patch.object(lists._OPENER, "open",
                                                              return_value=FakeResponse([b"x"] * 50)), \
                mock.patch.object(lists.time, "monotonic", side_effect=lambda: next(clock)):
            with self.assertRaisesRegex(lists.FetchError, "over 120 s"):
                lists.fetch("https://lists.example/a.m3u")

    def test_research_header_text(self):
        cases = {
            "UA: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/1": ('{"User-Agent":"Mozilla/5.0 (Windows NT 10.0; '
                                                                  'Win64; x64) Chrome/1"}', True),
            "Origin=https://o.example|Referer=https://o.example/|UA=VLC/3.0 LibVLC":
                ('{"Origin":"https://o.example","Referer":"https://o.example/","User-Agent":"VLC/3.0 LibVLC"}', True),
            "User-Agent=Mozilla/5.0 Chrome/134;Referer=https://d.example/":
                ('{"User-Agent":"Mozilla/5.0 Chrome/134","Referer":"https://d.example/"}', True),
            "Referer https://t.example/; Authorization Bearer (per-channel)": ('{"Referer":"https://t.example/"}', False),
            "UA otg/1.5.1 (see above)": ('{"User-Agent":"otg/1.5.1"}', False),
            "UA=UA": ("-", False), "UA Chrome": ("-", False), "some UA=UA": ("-", False),
            "X-Plex-Token required": ("-", False), "Referer ftp://f.example/": ("-", False),
            "UA=Mozilla/5.0; Cookie: s=abc": ("-", False), "UA Mozilla/5.0 |Authorization=Bearer x": ("-", False),
            "UA okhttp/4.9 Authorization Bearer 9f8e7d": ("-", False), "UA Mozilla/5.0 (x; Cookie: s=1)": ("-", False),
            "UA: Mozilla/5.0 (X11; rv:93.0) Gecko/20100101 Firefox/93.0":
                ('{"User-Agent":"Mozilla/5.0 (X11; rv:93.0) Gecko/20100101 Firefox/93.0"}', True),
            "Referer https://a.example/; Referer https://b.example/": ('{"Referer":"https://a.example/"}', False),
            "UA x/" + "1" * 1200: ('{"User-Agent":"x/' + "1" * 998 + '"}', False),
            "none listed": ("-", True)}
        for text, expected in cases.items():
            self.assertEqual(lists.headers_from_text(text), expected, text)

    def test_a_fetch_that_never_answers_ends_at_the_deadline(self):
        hang = mock.patch.object(lists._OPENER, "open", side_effect=lambda *a, **k: time.sleep(5))
        with resolving_to("93.184.216.34"), hang, mock.patch.object(lists, "FETCH_DEADLINE", 0.2):
            started = time.monotonic()
            with self.assertRaisesRegex(lists.FetchError, "over 0.2 s"):
                lists.fetch("https://lists.example/a.m3u")
        self.assertLess(time.monotonic() - started, 2)
        with resolving_to("93.184.216.34"), mock.patch.object(lists._OPENER, "open", side_effect=KeyError("bug")):
            with self.assertRaises(KeyError):  # an unexpected error surfaces as itself, not as a timeout
                lists.fetch("https://lists.example/a.m3u")

    def test_empty_header_values_are_dropped(self):
        self.assertEqual(lists.headers_cell([("Referer", " "), ("User-Agent", "UA")]), '{"User-Agent":"UA"}')

    def test_unreadable_urls_and_lone_surrogates_do_not_abort_a_run(self):
        data = [{"name": "Bad", "url": "http://[x/a.m3u8"}, {"name": "S\ud800", "url": "https://a.example/s.m3u8"},
                {"name": "T", "url": "https://a.example/\ud800.m3u8"}]
        rows = list(lists.parse_json_list(data, SOURCE))
        self.assertEqual([(r["name"], r["url"]) for r in rows], [("S\ufffd", "https://a.example/s.m3u8")])
        with tempfile.TemporaryDirectory() as d:
            good, bad = Path(d) / "a.tsv", Path(d) / "b.tsv"
            with self.assertRaises(UnicodeEncodeError):
                extract_research.write_all({good: "fine", bad: "x\ud800"})
            self.assertFalse(good.exists())

    def test_leading_comma_extinf_keeps_attributes_out_of_the_name(self):
        rows = list(lists.parse_m3u('#EXTINF:-1,tvg-id="X.us",tvg-logo="https://l.example/x.png",X News\n'
                                    "https://x.example/x.m3u8\n", SOURCE))
        self.assertEqual((rows[0]["name"], rows[0]["tvg_id"]), ("X News", "X.us"))
        rows = list(lists.parse_m3u('#EXTINF:-1 tvg-logo= "https://l.example/y.png" , Y TV | HD\nhttps://y.example/y\n',
                                    SOURCE))
        self.assertEqual(rows[0]["name"], "Y TV | HD")

    def test_unquoted_and_half_quoted_extinf_attributes_stay_out_of_the_name(self):
        rows = list(lists.parse_m3u(
            '#EXTINF:-1 tvg-chno=69 tvg-id="enquetes" group-title="Séries",ENQUÊTES DE CHOC\nhttps://a.example/a\n'
            '#EXTINF:-1 tvg-id=Action 24.gr" tvg-logo="https://l.example/a.png?raw=true" group-title="Regional",'
            'Action 24\nhttps://b.example/b\n'
            "#EXTINF:-1 tvg-id=SomeAdult.us group-title=Adult,Neutral Name\nhttps://cdn.example.org/c.m3u8\n", SOURCE))
        self.assertEqual([(r["name"], r["tvg_id"], r["category"]) for r in rows],
                         [("ENQUÊTES DE CHOC", "enquetes", "Séries"), ("Action 24", "Action 24.gr", "Regional"),
                          ("Neutral Name", "SomeAdult.us", "Adult")])
        self.assertEqual(verdict(rows[2], ALLOW).bucket, "nsfw")  # the unquoted group-title reaches the rules

    def test_hostile_lines_and_values_parse_in_linear_time(self):
        started = time.monotonic()
        for line in ("#EXTINF:" + "a" * 200_000, "#EXTINF:-1 " + "tvg-a " * 40_000 + ",N",
                     '#EXTINF:-1 a="' + "x" * 200_000, "#EXTINF:-1 " + "a=" * 100_000 + ",N"):
            list(lists.parse_m3u(line + "\nhttps://a.example/a\n", SOURCE))
        for line in ("#EXTINF:-1 " + "a" * 100_000 + ",N", "#EXTINF:-1 " + "a:/" * 30_000 + ",N"):  # URL_IN_TEXT
            list(lists.parse_m3u(line + "\nhttps://a.example/a\n", SOURCE))
        for text in ("http://h/?" + ";" * 1300 + "=" + ":" * 2700 + "x", "http://h/?" + ";a" * 2000 + "=1",
                     "http://h/a?" + "?" * 100_000 + "=1", "http://h/a?k=" + "eyJ" * 33_000,
                     "http://h/a?" + "token" * 20_000 + ".=1", "http://h/a?k=" + ".eyJ" * 25_000,
                     "http://h/a/" + "0" * 32 + "/" + "1" * 100_000 + "x"):
            self.assertFalse(rules.token_shaped(text))
        self.assertFalse(rules._personal_jwt("eyJ" * 20_000))
        self.assertFalse(rules._personal_jwt(".eyJ" * 25_000))
        list(lists.parse_m3u("#EXTINF:-1," + "tvg-a=x," * 25_000 + "N\nhttps://a.example/a\n", SOURCE))
        self.assertLess(time.monotonic() - started, 5)  # quadratic regexes took minutes here

    def test_every_text_of_an_extinf_entry_reaches_the_nsfw_rules(self):
        rows = list(lists.parse_m3u(
            '#EXTINF:-1 tvg-logo="https://l.example/a.png group-title="XXX",Ch 1\nhttps://cdn.example.org/1.m3u8\n'
            "#EXTINF:-1,group-title=Adult,Hot Night\nhttps://cdn.example.org/2.m3u8\n"
            "#EXTINF:-1 group-title=Adult\nhttps://cdn.example.org/3.m3u8\n"
            "#EXTINF:-1 radio=true,Plain\nhttps://cdn.example.org/4.m3u8\n"
            "#EXTINF:-1,tvg-id=Brazzers.us Brazzers TV\nhttps://cdn.example.org/5.m3u8\n"  # the name swallowed
            "#EXTINF:-1 tvg-id=x.us Hot XXX\nhttps://cdn.example.org/6.m3u8\n"
            '#EXTINF:-1 group-title="Movies",Neutral\n#EXTGRP:XXX\nhttps://cdn.example.org/7.m3u8\n'
            '#EXTINF:-1 tvg-name="Penthouse HD",Late\nhttps://cdn.example.org/8.m3u8\n'
            "https://cdn.example.org/9.m3u8\n"  # a second URL of the entry before
            "#EXTINF:-1,Next\nhttps://cdn.example.org/10.m3u8\nhttps://cdn.example.org/11.m3u8\n", SOURCE))
        self.assertEqual([(r["name"], r["category"]) for r in rows],
                         [("Ch 1", "nsfw"), ("Hot Night", "Adult"), ("-", "Adult"), ("Plain", "-"), ("-", "nsfw"),
                          ("-", "nsfw"), ("Neutral", "Movies; XXX"), ("Late", "nsfw"), ("-", "nsfw"), ("Next", "-"),
                          ("-", "-")])
        self.assertEqual([verdict(r, ALLOW).bucket for r in rows],
                         ["nsfw", "nsfw", "nsfw", "public", "nsfw", "nsfw", "nsfw", "nsfw", "nsfw", "public", "public"])

    def test_a_long_group_title_does_not_cut_an_nsfw_signal(self):
        long = "; ".join(f"Genre {n}" for n in range(40))
        rows = list(lists.parse_m3u(f'#EXTINF:-1 group-title="{long}",N\n#EXTGRP:XXX\nhttps://cdn.example.org/1.m3u8\n',
                                    SOURCE))
        self.assertEqual(verdict(rows[0], ALLOW).bucket, "nsfw")
        self.assertTrue(rows[0]["category"].startswith("nsfw; Genre 0"))

    def test_leading_comma_bare_values_lose_their_separating_comma(self):
        rows = list(lists.parse_m3u("#EXTINF:-1,tvg-id=CNN.us,tvg-country=US,group-title=News,CNN\n"
                                    "https://x.example/x.m3u8\n", SOURCE))
        self.assertEqual((rows[0]["name"], rows[0]["tvg_id"], rows[0]["country"], rows[0]["category"]),
                         ("CNN", "CNN.us", "US", "News"))

    def test_json_categories_run_from_the_node_to_its_ancestors(self):
        data = {"groups": [{"group": "XXX", "channels": [{"name": "N", "genre": "Movies",
                                                          "url": "https://cdn.example.org/n.m3u8"}]},
                           {"name": "News", "categories": ["news", 5, "world"], "url": "https://cdn.example.org/w.m3u8"}]}
        rows = list(lists.parse_json_list(data, SOURCE))
        self.assertEqual([(r["name"], r["category"]) for r in rows], [("N", "Movies; XXX"), ("News", "news; world")])
        self.assertEqual([verdict(r, ALLOW).bucket for r in rows], ["nsfw", "public"])

    def test_long_json_ancestors_do_not_cut_an_nsfw_category(self):
        genres = [f"Genre {n}" for n in range(40)]  # over MAX_NAME once joined
        child = {"name": "Neutral", "genre": "XXX", "url": "https://cdn.example.org/n.m3u8"}
        middle = {"categories": genres, "channels": [{"name": "Deep", "genre": "Movies",
                                                      "url": "https://cdn.example.org/d.m3u8"}]}
        rows = list(lists.parse_json_list({"categories": genres, "channels": [child]}, SOURCE))
        rows += lists.parse_json_list({"group": "XXX", "sections": [middle]}, SOURCE)
        self.assertEqual([verdict(r, ALLOW).bucket for r in rows], ["nsfw", "nsfw"])
        self.assertTrue(all(len(r["category"]) <= lists.MAX_NAME for r in rows))

    def test_json_nsfw_signals_beyond_name_and_category(self):
        data = {"groups": [
            {"name": "XXX Channels", "channels": [{"name": "Ch 1", "url": "https://cdn.example.org/1.m3u8"}]},
            {"name": "Ch 2", "description": "Hustler late night", "url": "https://cdn.example.org/2.m3u8"},
            {"name": "Ch 3", "is_adult": True, "url": "https://cdn.example.org/3.m3u8"},
            {"name": "Ch 4", "channel": "CNN.us", "nsfw": False, "logo": "https://i.example/7IxXX6f.png",
             "youtube": "UCXXxRHhOXI6xFu8kDwV5UnQ", "url": "https://cdn.example.org/4.m3u8"},  # run 15 id
            {"name": "Ch 5", "title": "HotXXX", "url": "https://cdn.example.org/5.m3u8"},  # a glued xxx in a name key
            {"name": "Ch 6", "tvg_name": "Late HotXXX", "url": "https://cdn.example.org/6.m3u8"},
            {"name": "Ch 7", "title": "https://i.example/7IxXX6f.png", "url": "https://cdn.example.org/7.m3u8"}]}
        rows = list(lists.parse_json_list(data, SOURCE))
        self.assertEqual([verdict(r, ALLOW).bucket for r in rows],
                         ["nsfw", "nsfw", "nsfw", "public", "nsfw", "nsfw", "public"])
        self.assertEqual(rows[3]["tvg_id"], "CNN.us")

    def test_german_and_french_erotic_names(self):
        for name in ("Erotik Kanal", "Cin\u00e9 \u00e9rotique", "Canal Er\u00f3tico"):
            self.assertEqual(verdict(copy("https://cdn.example.org/live/c.m3u8", name=name), ALLOW).bucket, "nsfw", name)

    def test_pluto_de_adult_group_is_nsfw(self):
        index = {"regions": {"de": {"channels": {PLUTO_ID: {"name": "Pluto TV Stimulierende Dokus",
                                                            "group": "Sinnliche Fantasien"}}}}}
        row = next(lists.fast_rows("pluto", index))
        self.assertEqual(verdict(row, ALLOW).bucket, "nsfw")
        listed = copy("https://cdn.example.org/a.m3u8", category="Pluto DE: Sinnliche Fantasien")  # free text
        self.assertEqual(verdict(listed, ALLOW).bucket, "nsfw")

    def test_json_tvg_id_carry_scalar_adult_flags_and_text_without_urls(self):
        data = {"channel": "Adult.us", "sources": [{"file": "https://cdn.example.org/1.m3u8"}],
                "more": [{"name": "A", "adult": "yes", "url": "https://cdn.example.org/2.m3u8"},
                         {"name": "B", "is_nsfw": 1, "url": "https://cdn.example.org/3.m3u8"},
                         {"name": "C", "adult": {"adult": "true"}, "url": "https://cdn.example.org/4.m3u8"},
                         {"name": "D", "notes": "https://x.example/p Hustler late night", "url": "https://cdn.example.org/5.m3u8"}]}
        rows = list(lists.parse_json_list(data, SOURCE))
        self.assertEqual([r["tvg_id"] for r in rows], ["Adult.us"] * 5)
        # C: a dict-valued flag is no flag, and its nested {"adult": "true"} marks only its own children (the
        # scalar-only read is a cost fix, pinned by test_deep_nesting_does_not_recurse)
        self.assertEqual([verdict(r, ALLOW).bucket for r in rows], ["public", "nsfw", "nsfw", "public", "nsfw"])

    def test_m3u_tvg_name_meets_the_name_rule_without_its_urls(self):
        rows = list(lists.parse_m3u(
            '#EXTINF:-1 tvg-name="HotXXX TV",Late\nhttps://cdn.example.org/1.m3u8\n'  # a glued "xxx"
            "#EXTINF:-1 tvg-name=Foo logo=http://i.imgur.com/7IxXX6f.png,Foo\nhttps://cdn.example.org/2.m3u8\n",
            SOURCE))
        self.assertEqual([verdict(r, ALLOW).bucket for r in rows], ["nsfw", "public"])

    def test_a_json_drm_key_marks_its_own_urls_only(self):
        # run 12 shapes: teleonline's root "license" is its content licence; Zappr's clearkey channel has a non-DRM
        # fallback
        data = {"license": {"source": "Lists Example", "terms": "CC BY 4.0"},
                "channels": [{"name": "La 1", "url": "https://cdn.example.org/la1.m3u8"},
                             {"name": "HR", "url": "https://cdn.example.org/hr/cenc-default.m3u8", "license": "clearkey",
                              "fallback": {"url": "https://cdn.example.org/hr/fallback.m3u8"}}]}
        self.assertEqual([(r["url"].rsplit("/", 1)[1], r["notes"]) for r in lists.parse_json_list(data, SOURCE)],
                         [("la1.m3u8", "-"), ("cenc-default.m3u8", "license key (DRM)"), ("fallback.m3u8", "-")])

    def test_logo_urls_and_adult_in_names_are_not_nsfw_signals(self):
        rows = list(lists.parse_m3u(  # run 12 lines that went nsfw on a whole-line category check
            '#EXTINF:-1 tvg-name="Max Sport 4" tvg-logo="https://i.imgur.com/7IxXX6f.png" group-title="Sports",'
            'Max Sport 4\nhttps://cdn.example.org/1.m3u8\n'
            '#EXTINF:-1 tvg-name="Pluto TV Adult Animation" group-title="Animation",Pluto TV Adult Animation\n'
            'https://cdn.example.org/2.m3u8\n'
            '#EXTINF:-1 tvg-id="Adult Swim" tvg-logo="https://i.ibb.co/k/logo-Adult-Swim.png" group-title="TV",'
            'Adult Swim | Mexico\nhttps://cdn.example.org/3.m3u8\n#EXTINF:-1,Pop Adult\nhttps://cdn.example.org/4.m3u8\n',
            SOURCE))
        self.assertEqual([verdict(r, ALLOW).bucket for r in rows], ["public"] * 4)

    def test_other_host_json_is_never_parsed(self):
        body = lists.Fetched(SOURCE, SOURCE, b'[{"name": "A", "url": "https://a.example/a.m3u8"}]')
        with mock.patch.object(lists.json, "loads", side_effect=AssertionError("parsed")):
            self.assertEqual(lists.parse_list(body, m3u_only=True), ("not-a-list", []))


class RulesTest(unittest.TestCase):
    """Verdict rules (rules.py, allowlist.py): credentials, tokens, NSFW, static sources, host admission."""

    def test_short_form_panel_urls_neither_vouch_nor_get_host_admission(self):
        allow = Allowlist(["http://198.51.100.7:826/1368/pw/1672"], parse_reviewed(""), vouches)
        self.assertIsNone(allow.admit("http://198.51.100.7:826/other.user/pw2/120160"))
        self.assertIsNone(ALLOW.admit("https://cdn.example.org/hls/KBS/03.m3u8"))  # host admitted, shape is not
        self.assertEqual(ALLOW.admit("https://cdn.example.org/live/c.m3u8"), "iptv-org-host")

    def test_requester_bound_and_encoded_keys_are_minted(self):
        for url in ("https://cdn.example.org/a.m3u8?ads.ip=203.0.113.9&w=1",
                    "https://cdn.example.org/a.m3u8?ads.streaming_id=0b1c",
                    "https://cdn.example.org/a.m3u8?ads.vizdartoken=0b1c&ads.apikey=1",
                    "https://cdn.example.org/a.m3u8?tp%3Dx%26apikey%3D0123abcd"):
            self.assertEqual(verdict(copy(url), ALLOW), rules.Verdict("private", "minted"), url)

    def test_an_encoded_credential_in_a_published_cell_is_caught(self):
        source = SOURCE + "?src=" + b64("http://user:pw@198.51.100.5/live.m3u8")
        self.assertEqual(verdict(copy("https://cdn.example.org/a.m3u8", source), ALLOW),
                         rules.Verdict("private", "credential", True))

    def test_nested_or_value_shaped_personal_claims(self):
        for claims in ({"data": {"mobile": "0700000000"}}, {"sub": "someone@example.com"}, {"x": ["+44 20 7946 0000"]}):
            token = "eyJhbGciOiJIUzI1NiJ9." + b64(json.dumps(claims)) + ".sig"
            self.assertEqual(rules.url_rejection(f"https://iptv.example/a.m3u8?t={token}"), ("private", "credential"))

    def test_free_text_adult_categories(self):
        # "xxx", "adult", "erotic" and "nsfw" as whole category tokens (a token set until round 8) included
        for category in ("XXX Movies", "Adult Channels", "18+", "news;Porn", "xxx", "news; adult", "Erotic", "nsfw"):
            self.assertTrue(rules.nsfw_category(category), category)
        for category in ("Adult Swim", "general", "-"):
            self.assertFalse(rules.nsfw_category(category), category)

    def test_every_published_cell_is_scanned(self):
        for cells in ({"name": "X ?token=abc"}, {"category": "http://u:p@198.51.100.5/"}, {"language": "?sig=1"}):
            self.assertEqual(verdict(copy("https://cdn.example.org/a.m3u8", **cells), ALLOW).copy_only, True, cells)

    def test_d14_hosts_are_static_for_m3u_files_only(self):
        url = "https://cdn.example.org/live/c.m3u8"
        self.assertEqual(verdict(copy(url, "https://www.apsattv.com/xumo.m3u"), ALLOW).bucket, "public")
        self.assertEqual(verdict(copy(url, "https://www.apsattv.com/api/live.json"), ALLOW),
                         rules.Verdict("private", "minted", True))

    def test_more_requester_values_and_token_keys(self):
        for query in ("ads.ip=2a02:1:2:3:4:5:6:7", "ip=2001:db8::1", "ip=203.0.113.9:8080", "token_id=1", "v2token=1"):
            self.assertEqual(verdict(copy(f"https://cdn.example.org/a.m3u8?{query}"), ALLOW).reason, "minted", query)
        self.assertEqual(verdict(copy("https://cdn.example.org/a.m3u8?start=12:30:45"), ALLOW).reason,
                         "unreviewed-query")  # not minted: a time, not an address

    def test_short_form_variants_and_refs_heads_duplicates(self):
        allow = Allowlist(["http://198.51.100.7:826/a/b/1"], parse_reviewed(""), vouches)
        for path in ("//u/p/120160", "/u/p/%31%32"):
            self.assertIsNone(allow.admit(f"http://198.51.100.7:826{path}"), path)
        self.assertEqual(lists.list_target(research("https://raw.githubusercontent.com/o/r/refs/heads/main/a.m3u")),
                         ("https://raw.githubusercontent.com/o/r/main/a.m3u", "static"))

    def test_long_form_xtream_with_merged_slashes_is_a_credential(self):
        for url in ("http://198.51.100.7:8080//live/user/pass/5.ts", "http://198.51.100.7:8080/live//user/pass/5.ts"):
            self.assertEqual(rules.url_rejection(url), ("private", "credential"), url)

    def test_an_ip_value_inside_a_json_or_text_cell_and_the_kind_cell_are_scanned(self):
        url = "https://cdn.example.org/live/c.m3u8"
        for cells in ({"headers": '{"Referer":"https://site.example/player?ads.ip=198.51.100.9"}'},
                      {"notes": "plays via ?ip=198.51.100.9 only"}, {"kind": "stream ?token=ab12"}):
            self.assertEqual(verdict(copy(url, **cells), ALLOW), rules.Verdict("private", "minted", True), cells)


class PathTokenTest(unittest.TestCase):
    """D16: token and DRM shapes in the path of a URL iptv-org does not list verbatim."""

    def test_signed_and_session_paths_are_minted(self):
        webcaster = ("https://cdn.example.org/media/playlist/free_672d700f2f9510be660253786e4406fe_hd/33_85479982/1080p/"
                     "4eaec8986e2012fb936478856fbf3b4b/4818731006.m3u8")
        for url in ("https://cdn.example.org/_token/v1.1790056588.nji8saooj4L1tbq7mfidDHdtnEaKU9-Igx3QHhVVgXc/i.m3u8",
                    "https://cdn.example.org/v1/master/0547f1/prod/bitok/eyJzdGlkIjoiMDEyMyJ9/playlist.m3u8",
                    "https://cdn.example.org/live/c.m3u8#token=ab12",  # a fragment key
                    webcaster, "https://cdn.example.org/live/69393EAE6ADBC65A68F942022362A202/13.m3u8",
                    "https://cdn.example.org/tok_eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjF9.c2ln/live/a.m3u8"):  # a glued JWT
            self.assertEqual(verdict(copy(url), ALLOW), rules.Verdict("private", "minted"), url)
        for url in ("https://cdn.example.org/e64d564b9275484f85981d8c146fb915/us-east-1/5994000126001/profile_1/"
                    "976f34cf5a614518b7b539cbf9812080/chunklist_ssaiV.m3u8",  # a Brightcove SSAI session
                    "https://cdn.example.org/9bb0f4edcb8946e79f5017ddca6c02b0/" + "26af5488" * 8 + ".m3u8"):
            self.assertEqual(verdict(copy(url), ALLOW), rules.Verdict("private", "minted"), url)
        self.assertEqual(verdict(copy("https://cdn.example.org/live/c.m3u8#t=0.1"), ALLOW).bucket, "public")
        listed = Allowlist([webcaster], parse_reviewed(""), vouches)
        self.assertEqual(verdict(copy(webcaster), listed).bucket, "public")  # iptv-org's exact URL
        for url in ("https://cdn.example.org/brightcove/0123456789abcdef0123456789abcdef/us-east-1/a.m3u8",
                    "https://cdn.example.org/0123456789abcdef0123456789abcdef/index.m3u8"):
            self.assertEqual(verdict(copy(url), ALLOW).bucket, "public", url)

    def test_long_token_key_runs_keep_their_verdicts(self):
        for key, minted in (("token" * 3 + "_id", True), ("token" * 3 + ".x", False), ("Wowzatokenhash", True),
                            ("aws.sessionId", True), ("x-amz-signature", True), ("ads.apikey", True), ("tokens.x", False)):
            self.assertEqual(rules.token_shaped(f"https://cdn.example.org/a.m3u8?{key}=1"), minted, key)

    def test_drm_named_in_the_path_is_drm_unless_iptv_org_lists_the_url(self):
        for url in ("https://cdn.example.org/LA7D/DRM/HLS/Live.m3u8", "https://cdn.example.org/m6/cmaf_cenc00/d.mpd",
                    "https://cdn.example.org/hisi_axn/playlist_cbcs.mpd"):
            self.assertEqual(verdict(copy(url), ALLOW), rules.Verdict("private", "drm"), url)
        listed = Allowlist(["https://cdn.example.org/drm/smil:tv.smil/index.m3u8"], parse_reviewed(""), vouches)
        self.assertEqual(verdict(copy("https://cdn.example.org/drm/smil:tv.smil/index.m3u8"), listed).bucket, "public")
        for url in ("https://cdn.example.org/live_drm/index.mpd", "https://cdn.example.org/drm1/index.mpd"):
            self.assertEqual(verdict(copy(url), ALLOW), rules.Verdict("private", "drm"), url)
        for url in ("https://cdn.example.org/live/licencia.m3u8", "https://cdn.example.org/nondrm/a.m3u8"):
            self.assertEqual(verdict(copy(url), ALLOW).bucket, "public", url)  # "cenc", "drm" inside words

    def test_kodi_drm_pairs_and_pipe_suffixes(self):
        rows = list(lists.parse_m3u("#EXTINF:-1,A\nhttps://a.example/a.mpd|drmScheme=clearkey&drmLicense=k:v\n",
                                    SOURCE))
        self.assertEqual(rows[0]["notes"], "license pair (DRM)")
        rows = list(lists.parse_json_list([{"name": "B", "url": "https://b.example/b.mpd|drmLicense=k:v"}], SOURCE))
        self.assertEqual(rows[0]["notes"], "license key (DRM)")
        rows = list(lists.parse_m3u("#EXTINF:-1,C\nhttps://c.example/c.mpd|drmScheme=widevine\n#EXTINF:-1,D\n"
                                    "https://d.example/d.mpd|Kodi=clearkey\n", SOURCE))
        self.assertEqual([r["notes"] for r in rows], ["license pair (DRM)"] * 2)  # a name or a value alone
        self.assertEqual(verdict(copy("https://cdn.example.org/a.m3u8|Cookie=sessid=abc"), ALLOW).reason,
                         "unreviewed-query")  # a research URL keeps its suffix verbatim

    def test_token_shaped_list_urls_are_never_fetched(self):
        url = "https://lists.example/stitch/playlist.m3u?jwt=eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjF9.sig"
        self.assertEqual(lists.list_target(research(url)), (None, "skip:token"))


class QueryAllowlistTest(unittest.TestCase):
    """D15: a public row that is not an exact iptv-org URL carries no query string."""

    def test_parameters_on_admitted_hosts_are_private(self):
        allow = Allowlist(["https://iptv.example/a.m3u8", "https://cdn.example.org/b.m3u8"],
                          parse_reviewed("x.example"), vouches)
        for url in ("https://cdn.example.org/parliament/hls/webtv.m3u8?hsesid=69f6b557c7fd6782cfc365706424e3c9",
                    "https://jmp2.uk/plu-5ad8d3a31b95267e225e4e09.m3u8?ads=1",  # fast-host
                    "https://x.example/a.m3u8?id=1",  # reviewed-host
                    "https://cdn.example.org/a.m3u8;foo=1", "https://cdn.example.org/a.m3u8%3Fid=1",
                    "https://cdn.example.org/a.m3u8%253Fid=1"):
            self.assertEqual(verdict(copy(url), allow), rules.Verdict("private", "unreviewed-query"), url)
        list_row = copy("https://x.example/list.m3u?type=m3u", kind="list-endpoint")
        self.assertEqual(verdict(list_row, allow).reason, "unreviewed-query")

    def test_exact_iptv_org_urls_fragments_and_bare_question_marks_stay_public(self):
        allow = Allowlist(["https://iptv.example/a.m3u8?id=1", "https://cdn.example.org/b.m3u8"],
                          parse_reviewed(""), vouches)
        for url in ("https://iptv.example/a.m3u8?id=1", "https://cdn.example.org/c.m3u8#skym3u.dev",
                    "https://cdn.example.org/c.m3u8?"):
            self.assertEqual(verdict(copy(url), allow).bucket, "public", url)

    def test_a_clean_copy_does_not_promote_a_query_url(self):
        url = "https://cdn.example.org/live/q.m3u8?id=1"
        row = merged(copy(url, "https://raw.githubusercontent.com/zokerpunk/x/a.m3u"), copy(url))[url]
        self.assertEqual((row["_bucket"], row["reason"]), ("private", "unreviewed-query"))


STREAMS = [
    {"url": "https://iptv.example/a.m3u8", "channel": "CNN.us", "feed": "East"},
    {"url": "https://iptv.example/live/b.m3u8?token=1", "channel": "BBC.uk", "feed": None},
    {"url": "https://shared.example/play.php?id=1", "channel": "One.fr", "feed": None},
    {"url": "https://shared.example/play.php?id=2", "channel": "Two.fr", "feed": None},
    {"url": f"https://jmp2.uk/plu-{PLUTO_ID}.m3u8", "channel": "PlutoNews.us", "feed": None},
    {"url": "http://198.51.100.1:8000/live/x.m3u8", "channel": "Port.us", "feed": None},
]
CHANNELS = [
    {"id": "CNN.us", "name": "CNN", "alt_names": [], "country": "US", "categories": ["news"], "is_nsfw": False},
    {"id": "BBC.uk", "name": "BBC One", "alt_names": ["BBC 1"], "country": "UK", "categories": ["general"]},
    {"id": "Blocked.es", "name": "Futbol Max", "alt_names": [], "country": "ES", "categories": ["sports"]},
    {"id": "Adult.us", "name": "Late Show", "alt_names": [], "country": "US", "categories": ["xxx"], "is_nsfw": True},
    {"id": "Twin.de", "name": "Twin", "alt_names": [], "country": "DE"},
    {"id": "Twin2.de", "name": "TWIN HD", "alt_names": [], "country": "DE"},
]
BLOCKLIST = [{"channel": "Blocked.es", "reason": "dmca"}]


def pool_row(url, name="-", country="-", bucket="public"):
    values = dict.fromkeys(COLUMNS, "-")
    values.update(url=url, name=name, country=country, _bucket=bucket, reason="iptv-org-host")
    return values


class ChannelsTest(unittest.TestCase):
    join = Channels(STREAMS, CHANNELS, BLOCKLIST)

    def key(self, url, tvg_id="", name="-", country="-"):
        return self.join.key(pool_row(url, name, country), tvg_id)

    def test_key_order(self):
        self.assertEqual(self.key("https://iptv.example/a.m3u8", "BBC.uk"), "CNN.us@East")  # exact URL first
        # host+path: never where iptv-org's own URL on the path has a query (it may name the channel)
        self.assertEqual(self.key("https://iptv.example/live/b.m3u8?token=2"), "")
        self.assertEqual(self.key("https://shared.example/play.php?id=3"), "")  # host+path used by two channels
        self.assertEqual(self.key(f"https://stitcher.pluto.tv/v1/stitch/hls/channel/{PLUTO_ID}/master.m3u8"),
                         "PlutoNews.us")  # provider id mapped
        self.assertEqual(self.key("https://jmp2.uk/stvp-GB1"), "samsung:gb1")
        self.assertEqual(self.key("https://other.example/x.m3u8", "cnn.US@SD"), "CNN.us")  # tvg-id
        self.assertEqual(self.key("https://other.example/y.m3u8", name="BBC 1 HD [Geo-blocked]", country="UK"),
                         "BBC.uk")  # name + country
        self.assertEqual(self.key("https://other.example/y.m3u8", name="BBC 1", country="INT"), "")
        self.assertEqual(self.key("https://other.example/z.m3u8", name="Twin", country="DE"), "")  # ambiguous name
        self.assertEqual(self.key("http://198.51.100.1:8001/live/x.m3u8"), "")  # another port is another host

    def test_host_path_keys_only_paths_iptv_org_lists_without_a_query(self):
        join = Channels([{"url": "https://fast.example/live/c.m3u8", "channel": "CNN.us"},
                         {"url": "https://ssai.example/s.m3u8?id=1", "channel": "BBC.uk"}], CHANNELS, [])
        self.assertEqual(join.key(pool_row("https://fast.example/live/c.m3u8?ads.app=1"), ""), "CNN.us")
        for url in ("https://ssai.example/s.m3u8?id=2", "https://ssai.example/s.m3u8"):
            self.assertEqual(join.key(pool_row(url), ""), "", url)
        adult = Channels([{"url": "https://ssai.example/a.m3u8?id=1", "channel": "Adult.us"}], CHANNELS, [])
        row = pool_row("https://ssai.example/a.m3u8")  # not keyed there, but the path's NSFW channel still flags it
        adult.apply(row, [])
        self.assertEqual((row["channel"], row["_bucket"]), ("", "nsfw"))

    def test_blocklist_nsfw_and_fills(self):
        blocked = pool_row("https://pirate.example/f.m3u8", name="Futbol Max", country="ES")
        self.join.apply(blocked, [])
        self.assertEqual((blocked["_bucket"], blocked["reason"], blocked["category"]),
                         ("private", "blocklist:dmca", "sports"))
        adult = pool_row("https://x.example/l.m3u8", bucket="private")
        self.join.apply(adult, ["Adult.us"])
        self.assertEqual((adult["_bucket"], adult["reason"], adult["country"]), ("nsfw", "nsfw", "US"))

    def test_a_copy_tvg_id_naming_an_nsfw_channel_counts_and_fills_are_cleaned(self):
        exact = pool_row("https://iptv.example/a.m3u8")  # resolves to CNN.us@East by exact URL
        self.join.apply(exact, ["CNN.us", "Adult.us"])
        self.assertEqual(exact["_bucket"], "nsfw")
        join = Channels(STREAMS, [{"id": "Tab.us", "name": "Tab", "country": "U\tS", "categories": ["news\nxxx"]}], [])
        row = pool_row("https://other.example/t.m3u8")
        join.apply(row, ["Tab.us"])
        self.assertEqual((row["country"], row["category"], row["_bucket"]), ("U S", "news xxx", "nsfw"))

    def test_nsfw_reaches_every_url_holding_the_fast_id_of_an_nsfw_row(self):
        lineup, channel = "608049aefa2b8ae93c2c3a63", "64695233f73356567a64ce90"
        other_channel = "6111b06a8f945c002c45dd12"
        proxied, roku, random_hex = "5f12345678abcdef01234567", "b484db42f3d31b6dc2f604d453c694a0", "ab" * 12
        nsfw = [pool_row(f"https://jmp2.uk/plu-{PLUTO_ID}.m3u8", bucket="nsfw"),
                pool_row(f"https://jmp2.uk/plex-{lineup}-{channel}.m3u8", bucket="nsfw"),
                pool_row("https://jmp2.uk/sam-USBC4400020H7.m3u8", bucket="nsfw"),
                pool_row(f"https://jmp2.uk/rok-{roku}.m3u8", bucket="nsfw"),
                # the only nsfw spelling of a channel: a proxy's encoded query value, an uppercase slug
                pool_row(f"https://proxy.example/p?u=https%3A%2F%2Fjmp2.uk%2FPLU-{proxied.upper()}.m3u8",
                         bucket="nsfw"),
                pool_row("https://jmp2.uk/stvp-GB1", bucket="nsfw"),  # too short to be an id
                pool_row(f"https://adult.example/{random_hex}/x.m3u8", bucket="nsfw"),  # hex that is no FAST id
                # a Plex lineup named as a channel: by a one-part Plex key, or shaped as a Pluto id
                pool_row(f"https://jmp2.uk/plex-{lineup}.m3u8", bucket="nsfw"),
                pool_row(f"https://jmp2.uk/plu-{lineup}.m3u8", bucket="nsfw")]
        reached = [
            pool_row(f"https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/{PLUTO_ID}/master.m3u8"),
            pool_row(f"https://i.mjh.nz/PlutoTV/{PLUTO_ID}-alt.m3u8"),
            pool_row(f"https://proxy.example/play?u=pluto%2Fchannel%2F{PLUTO_ID.upper()}%2Fm.m3u8"),  # a query value
            pool_row(f"https://i.mjh.nz/Plex/0123456789abcdef01234567-{channel}.m3u8", bucket="private"),  # lineup
            pool_row("https://i.mjh.nz/SamsungTVPlus/USBC4400020H7.m3u8"),
            pool_row(f"https://cdn.example.org/roku/{roku.upper()}/index.m3u8"),
            pool_row(f"https://jmp2.uk/plu-{proxied}.m3u8")]  # its canonical row
        kept = [pool_row(f"https://jmp2.uk/plu-{PLUTO_ID[::-1]}.m3u8"),  # another Pluto channel
                pool_row(f"https://jmp2.uk/plex-{lineup}-{other_channel}.m3u8"),  # same lineup, another channel
                pool_row(f"https://cdn.example.org/x{PLUTO_ID}.m3u8"),  # the id inside a longer word
                pool_row("https://jmp2.uk/stvp-GB1.m3u8"), pool_row("https://cdn.example.org/gb1/x.m3u8"),
                pool_row(f"https://cdn.example.org/{random_hex}/y.m3u8"),
                pool_row("https://adult.example/y.m3u8")]  # an nsfw non-FAST row's host
        for row in kept:
            row["channel"] = "Same.us"  # a shared channel key does not spread
        self.assertEqual(spread_nsfw(nsfw + reached + kept), (5, len(reached)))  # (ids spread, rows moved)
        self.assertEqual([(r["_bucket"], r["reason"]) for r in reached], [("nsfw", "nsfw")] * len(reached))
        self.assertEqual([r["_bucket"] for r in kept], ["public"] * len(kept))

    def test_any_copy_name_alt_names_blocklist_nsfw_and_an_empty_key(self):
        join = Channels(STREAMS, CHANNELS + [
            {"id": "Hidden.us", "name": "Hidden", "alt_names": ["Night Owl TV"], "country": "US"},
            {"id": "Tagged.us", "name": "Tagged Late", "country": "US", "categories": ["xxx"]}],
            BLOCKLIST + [{"channel": "Hidden.us", "reason": "nsfw"}])
        for name, names in (("Neutral", ["Neutral", "Night Owl TV"]), ("Tagged Late HD", [])):
            row = pool_row("https://other.example/q.m3u8", name=name)  # no key: empty
            join.apply(row, [], names)
            self.assertEqual((row["channel"], row["_bucket"]), ("", "nsfw"), name)

    def test_a_channel_the_owner_rules_nsfw_is_nsfw_by_key_tvg_id_and_name(self):
        # D21: iptv-org files FashionTV Secrets SFW; a list files a copy "Erotic"
        secrets = {"id": "FashionTVSecrets.fr", "name": "FashionTV Secrets", "alt_names": ["FTV Secrets"],
                   "country": "FR", "categories": ["lifestyle"], "is_nsfw": False}
        join = Channels([{"url": "https://ssai.example/s.m3u8?id=1", "channel": "FashionTVSecrets.fr", "feed": "HD"}],
                        CHANNELS + [secrets], [])
        exact, copied = pool_row("https://ssai.example/s.m3u8?id=1"), pool_row("https://other.example/s.m3u8")
        named = pool_row("https://other.example/n.m3u8", name="FTV Secrets HD")
        for row, tvg_ids in ((exact, []), (copied, ["FashionTVSecrets.fr"]), (named, [])):
            join.apply(row, tvg_ids)
        self.assertEqual([(r["_bucket"], r["reason"]) for r in (exact, copied, named)], [("nsfw", "nsfw")] * 3)
        neighbour = pool_row("https://ssai.example/s.m3u8?id=2", name="Kids TV")  # another channel on the endpoint
        join.apply(neighbour, [])
        self.assertEqual((neighbour["channel"], neighbour["_bucket"]), ("", "public"))  # no host+path key there

    def test_an_unidentified_row_named_like_an_nsfw_channel_is_nsfw(self):
        # D19 audit (run 13): Pluto DE erotic channels whose provider ids iptv-org maps to nothing
        fast = pool_row("https://jmp2.uk/plu-0123456789abcdef01234567.m3u8", name="Late Show HD", country="DE")
        self.join.apply(fast, [])
        self.assertEqual((fast["channel"], fast["_bucket"]), ("pluto:0123456789abcdef01234567", "nsfw"))
        identified = pool_row("https://iptv.example/a.m3u8", name="Late Show")  # CNN.us@East by its exact URL
        self.join.apply(identified, [])
        self.assertEqual(identified["_bucket"], "public")

    def test_helpers(self):
        self.assertEqual(name_key("ＢＢＣ One (720p) [Not 24/7] FHD"), "bbc one")
        self.assertEqual(provider_id("https://i.mjh.nz/%2Er/maori.m3u8"), "mjh:maori")
        self.assertIsNone(provider_id("https://jmp2.uk/other"))
        self.assertEqual(provider_id(f"https://i.mjh.nz/PlutoTV/{PLUTO_ID}-alt.m3u8"), f"pluto:{PLUTO_ID}")
        self.assertEqual(provider_id(f"https://jmp2.uk/PlutoTV/{PLUTO_ID}.m3u8"), f"pluto:{PLUTO_ID}")
        self.assertEqual(provider_id("https://i.mjh.nz/SamsungTVPlus/USBC4400020H7.m3u8"), "samsung:usbc4400020h7")
        plex_key = f"{PLUTO_ID[::-1]}-{PLUTO_ID}"
        self.assertEqual(provider_id(f"https://i.mjh.nz/Plex/{plex_key}.m3u8"), f"plex:{plex_key}")
        for url in ("https://i.mjh.nz/PlutoTV/.channels.json", "https://i.mjh.nz/PlutoTV/us.m3u8",
                    "https://i.mjh.nz/SamsungTVPlus/all.m3u8", f"https://i.mjh.nz/Plex/{PLUTO_ID}.m3u8"):
            self.assertIsNone(provider_id(url), url)  # playlists and a lone Plex lineup are no channel
        self.assertEqual(fast_id("https://i.mjh.nz/SamsungTVPlus/USBC4400020H7.m3u8"), "usbc4400020h7")
        self.assertEqual(fast_id(f"https://jmp2.uk/plex-{plex_key}.m3u8"), PLUTO_ID)  # channel part
        self.assertEqual(fast_id("https://jmp2.uk/rok-b484db42f3d31b6dc2f604d453c694a0.m3u8"),
                         "b484db42f3d31b6dc2f604d453c694a0")
        for url in ("https://i.mjh.nz/.r/maori.m3u8", "https://jmp2.uk/stvp-GB1", "https://jmp2.uk/rok-abc.m3u8",
                    "https://iptv.example/a.m3u8", f"https://jmp2.uk/plex-{PLUTO_ID}.m3u8"):
            self.assertIsNone(fast_id(url), url)

    def test_iptv_org_channel_strings_are_cleaned_and_a_later_tvg_id_keys_the_row(self):
        streams = [{"url": "https://p.example/live/a.m3u8", "channel": "Tab\t.us"},
                   {"url": f"https://jmp2.uk/plu-{PLUTO_ID}.m3u8", "channel": "New\nline.us"}]
        join = Channels(streams, CHANNELS, [])
        self.assertEqual(join.key(pool_row("https://p.example/live/a.m3u8?t=2"), ""), "Tab .us")
        self.assertEqual(join.key(pool_row(f"https://stitcher.pluto.tv/v1/stitch/hls/channel/{PLUTO_ID}/m.m3u8"), ""),
                         "New line.us")
        row = pool_row("https://other.example/k.m3u8")
        join.apply(row, ["foo", "cnn.us@East"])
        self.assertEqual(row["channel"], "CNN.us")


TEST_IP = "203.0.113.7"


class BuildPoolTest(unittest.TestCase):
    def run_main(self, remote: dict[str, bytes], seeds: dict[str, list[dict]], ips=(TEST_IP,), where=None):
        """Runs main with fetches answered from `remote`, in `where` (kept: a later run sees this one's outputs) or a
        fresh directory; returns (exit code, files written)."""
        def fetch(url):
            if url not in remote:
                raise lists.FetchError("HTTP Error 404: Not Found")
            return lists.Fetched(url, url, remote[url])

        with (tempfile.TemporaryDirectory() if where is None else contextlib.nullcontext(where)) as d:
            private = Path(d) / "priv"
            for bucket, rows in seeds.items():
                path = extract_research.seed_path(private, bucket)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("\n".join(["\t".join(OUT_COLUMNS)] + ["\t".join(r[c] for c in OUT_COLUMNS)
                                                                      for r in rows]) + "\n", encoding="utf-8")
            lookup = (mock.patch.object(egress, "known_ips", side_effect=egress.LookupFailed("down")) if ips is None
                      else mock.patch.object(egress, "known_ips", return_value=set(ips)))
            with mock.patch.object(lists, "fetch", side_effect=fetch), lookup, \
                    mock.patch.object(sys, "argv", ["x", str(Path(d) / "pub"), str(private)]), \
                    redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                code = build_pool.main()
            written = {p.name: p.read_text(encoding="utf-8") for p in Path(d).glob("p*/pool/*.tsv")}
        return code, written

    def remote(self, streams=None, m3u="") -> dict[str, bytes]:
        empty_fast = {"pluto": {"regions": {}}, "samsung": {"regions": {}}, "roku": {"channels": {}},
                      "plex": {"channels": {}}}
        files = {lists.IPTV_ORG_STREAMS: streams if streams is not None else STREAMS,
                 lists.IPTV_ORG_API + "channels.json": CHANNELS, lists.IPTV_ORG_API + "blocklist.json": BLOCKLIST}
        files.update({source: empty_fast[s] for s, (source, _) in lists.FAST_INDEXES.items()})
        out = {url: json.dumps(data).encode() for url, data in files.items()}
        if m3u:
            out[SOURCE] = m3u.encode()
        return out

    def seeds(self, *list_rows):
        values = {**dict.fromkeys(OUT_COLUMNS, "-"), "name": "Research", "url": "https://iptv.example/r.m3u8",
                  "kind": "stream", "reason": "iptv-org-host", "seen_in": "r/01"}
        values["source_page"] = values["url"]
        def pick(name):
            return [r for r in list_rows if r["_bucket"] == name]
        return {"public": [values] + pick("public"), "private": pick("private"), "nsfw": pick("nsfw")}

    def test_a_run_writes_the_pool_and_pull_records(self):
        m3u = ('#EXTINF:-1 tvg-id="BBC.uk",BBC\nhttps://iptv.example/live/b.m3u8?token=9\n'
               "#EXTINF:-1,Unknown\nhttps://unreviewed.example/u.m3u8\n"
               "#EXTINF:-1,CNN\nhttps://iptv.example/a.m3u8\n")
        code, written = self.run_main(self.remote(m3u=m3u), self.seeds(
            research(SOURCE, bucket="public", reason="reviewed-host"),
            research("https://gone.example/list.m3u"), research("https://iptv-org.github.io/iptv/index.m3u")))
        self.assertEqual(code, 0)
        self.assertEqual(sorted(written), ["nsfw.tsv", "private.tsv", "pulls.tsv", "streams.tsv"])
        public = {line.split("\t")[1]: dict(zip(OUT_COLUMNS + ["channel"], line.split("\t")))
                  for line in written["streams.tsv"].splitlines()[1:]}
        self.assertEqual(public["https://iptv.example/a.m3u8"]["seen_in"], "iptv-org,lists:1")
        self.assertEqual(public["https://iptv.example/a.m3u8"]["channel"], "CNN.us@East")
        self.assertEqual(public["https://iptv.example/r.m3u8"]["seen_in"], "research")
        self.assertIn("https://unreviewed.example/u.m3u8\t", written["private.tsv"])
        self.assertNotIn("token=9", written["streams.tsv"])  # minted (token URL, not iptv-org's exact string)
        pulls = [line.split("\t") for line in written["pulls.tsv"].splitlines()[1:]]
        self.assertEqual([(p[2], p[3].split(":")[0], p[4]) for p in pulls],
                         [("static", "m3u", "3"), ("other-host", "error", "0"), ("skip:iptv-org", "-", "0")])

    def buckets(self, seeds, body):
        """Runs main with SOURCE serving `body`; returns {url: file it was written to}."""
        remote = self.remote()
        remote[SOURCE] = body.encode()
        code, written = self.run_main(remote, seeds)
        self.assertEqual(code, 0)
        return {line.split("\t")[1]: name for name in ("streams.tsv", "private.tsv", "nsfw.tsv")
                for line in written[name].splitlines()[1:]}

    def test_rows_of_an_nsfw_or_listed_research_list_carry_its_verdict(self):
        body = "#EXTINF:-1,Late Night\nhttps://iptv.example/live/x.m3u8\n"
        nsfw = research(SOURCE, bucket="nsfw", reason="nsfw")  # NSFW by its name: the URL matches no rule
        self.assertEqual(self.buckets(self.seeds(nsfw), body)["https://iptv.example/live/x.m3u8"], "nsfw.tsv")
        # Listed by its source page, fetched from a URL no PRIVATE_HOSTS entry matches: refused (Spec 71 D9), since an
        # unreviewed-host verdict would outrank the copy-only taint and the monitor could fetch its rows.
        remote = self.remote()
        remote[SOURCE] = body.encode()
        code, written = self.run_main(remote, self.seeds(research(SOURCE, reason="listed:bplaytv/")))
        self.assertEqual((code, written), (1, {}))
        self.assertEqual(self.buckets(self.seeds(research(SOURCE, bucket="public", reason="reviewed-host")), body)
                         ["https://iptv.example/live/x.m3u8"], "streams.tsv")

    def test_a_research_stream_citing_an_nsfw_research_list_is_nsfw(self):
        seeds = self.seeds(research(SOURCE, bucket="nsfw", reason="nsfw"))
        seeds["public"][0]["source_page"] = SOURCE
        self.assertEqual(self.buckets(seeds, "")["https://iptv.example/r.m3u8"], "nsfw.tsv")

    def test_a_research_stream_citing_a_tainted_list_in_another_spelling_is_tainted(self):
        seeds = self.seeds(research(SOURCE, bucket="nsfw", reason="nsfw"))
        seeds["public"][0]["source_page"] = "https://github.com/someone/lists/blob/refs/heads/main/all.m3u"
        self.assertEqual(self.buckets(seeds, "")["https://iptv.example/r.m3u8"], "nsfw.tsv")

    def test_a_duplicate_target_keeps_the_strictest_taint(self):
        blob = research("https://github.com/someone/lists/blob/main/all.m3u", bucket="public", reason="reviewed-host")
        found = self.buckets(self.seeds(blob, research(SOURCE, bucket="nsfw", reason="nsfw")),
                             "#EXTINF:-1,A\nhttps://iptv.example/live/x.m3u8\n")
        self.assertEqual(found["https://iptv.example/live/x.m3u8"], "nsfw.tsv")

    def test_rows_keep_the_fetched_source_after_a_redirect(self):
        moved = "https://lists.example/all.m3u"  # a static URL redirected to a non-static host
        with mock.patch.object(lists, "fetch", side_effect=lambda u: lists.Fetched(u, moved, b"#EXTINF:-1,X\nhttps://x/a")):
            record, rows = build_pool._pull((research(SOURCE), SOURCE, "static"))
        self.assertEqual((record["fetched"], rows[0]["source_page"]), (moved, moved))

    def test_research_free_text_headers_become_json_and_the_rest_stays_in_notes(self):
        seeds = self.seeds()
        seeds["public"][0]["headers"] = "Referer https://t.example/; Authorization Bearer (per-channel)"
        code, written = self.run_main(self.remote(), seeds)
        row = next(dict(zip(OUT_COLUMNS + ["channel"], line.split("\t"))) for line in written["streams.tsv"].splitlines()
                   if "/r.m3u8\t" in line)
        self.assertEqual((row["headers"], row["notes"]), ('{"Referer":"https://t.example/"}',
                                                          "headers: a login or session header (not published)"))
        seeds["public"][0]["headers"] = "UA otg/1.5.1 (see above)"
        _, written = self.run_main(self.remote(), seeds)
        self.assertIn('{"User-Agent":"otg/1.5.1"}\t-\thttps://iptv.example/r.m3u8\theaders: UA otg/1.5.1 (see above)',
                      written["streams.tsv"])

    def test_research_header_text_naming_a_session_is_not_published(self):
        seeds = self.seeds()
        seeds["public"][0]["headers"] = "UA=Mozilla/5.0; Cookie: s=abc"
        _, written = self.run_main(self.remote(), seeds)
        self.assertNotIn("s=abc", written["streams.tsv"])
        self.assertIn("headers: a login or session header (not published)", written["streams.tsv"])

    def test_a_carried_row_meets_a_join_added_during_the_outage(self):
        m3u = '#EXTINF:-1 tvg-id="CNN.us",C\nhttps://iptv.example/live/c.m3u8\n'
        seeds = self.seeds(research(SOURCE, bucket="public", reason="reviewed-host"))
        with tempfile.TemporaryDirectory() as d:
            _, before = self.run_main(self.remote(m3u=m3u), seeds, where=d)
            remote = self.remote()  # the list fails, and iptv-org now blocklists the channel
            remote[lists.IPTV_ORG_API + "blocklist.json"] = json.dumps(
                BLOCKLIST + [{"channel": "CNN.us", "reason": "dmca"}]).encode()
            _, written = self.run_main(remote, seeds, where=d)
        self.assertIn("https://iptv.example/live/c.m3u8\t", before["streams.tsv"])
        self.assertIn("https://iptv.example/live/c.m3u8\t", written["private.tsv"])

    def test_a_list_that_fails_keeps_its_last_rows(self):
        m3u = ("#EXTINF:-1,Unknown\nhttps://unreviewed.example/u.m3u8\n"
               '#EXTINF:-1 tvg-id="Adult.us",Neutral\nhttps://iptv.example/live/n.m3u8\n'  # nsfw by tvg-id
               '#EXTINF:-1 tvg-id="Blocked.es",Plain\nhttps://iptv.example/live/p.m3u8\n')  # blocklisted by tvg-id alone
        seeds = self.seeds(research(SOURCE, bucket="public", reason="reviewed-host"),
                           research("https://never.example/l.m3u"))
        cited = {**seeds, "public": [{**seeds["public"][0], "source_page": SOURCE}] + seeds["public"][1:]}
        with tempfile.TemporaryDirectory() as d:
            first, before = self.run_main(self.remote(m3u=m3u), cited, where=d)
            seeds["public"][0]["url"] = "https://iptv.example/r2.m3u8"  # the research row citing SOURCE is gone
            code, written = self.run_main(self.remote(), seeds, where=d)  # SOURCE now fails
            again, rewritten = self.run_main(self.remote(), seeds, where=d)  # and fails again
        self.assertEqual((first, code, again), (0, 0, 0))
        self.assertIn("https://iptv.example/r.m3u8\t", before["streams.tsv"])
        for files in (written, rewritten):
            self.assertIn("https://unreviewed.example/u.m3u8\t", files["private.tsv"])
            self.assertIn("https://iptv.example/live/n.m3u8\t", files["nsfw.tsv"])  # never less strict when carried
            self.assertIn("https://iptv.example/live/p.m3u8\t", files["private.tsv"])
            urls = {line.split("\t")[1] for name in ("streams.tsv", "private.tsv", "nsfw.tsv")
                    for line in files[name].splitlines()[1:]}
            self.assertNotIn("https://iptv.example/r.m3u8", urls)  # a research row citing the list is not carried
            pulls = [line.split("\t") for line in files["pulls.tsv"].splitlines()[1:]]
            self.assertEqual([(p[1], p[3].split(":")[0], p[4]) for p in pulls],
                             [(SOURCE, "carried", "3"), ("https://never.example/l.m3u", "error", "0")])

    def test_a_failed_required_source_fails_before_writing(self):
        remote = self.remote()
        del remote[lists.FAST_INDEXES["roku"][0]]
        self.assertEqual(self.run_main(remote, self.seeds()), (1, {}))
        self.assertEqual(self.run_main(self.remote(streams={"not": "a list"}), self.seeds()), (1, {}))

    def test_swapped_repos_and_a_private_dir_inside_the_public_checkout_are_refused(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "pub" / "harvest").mkdir(parents=True)
            for private in (Path(d) / "pub", Path(d) / "pub" / "pool"):
                with mock.patch.object(build_pool, "fetch_required", side_effect=AssertionError("ran")), \
                        mock.patch.object(sys, "argv", ["x", str(Path(d) / "priv"), str(private)]), \
                        redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    build_pool.main()

    def test_the_egress_ip_in_a_public_row_fails_before_writing(self):
        url = "https://iptv.example/live/3405803783/a.m3u8"
        streams = STREAMS + [{"url": url, "channel": None, "feed": None, "title": "Leak"}]
        self.assertEqual(self.run_main(self.remote(streams=streams), self.seeds()), (1, {}))
        self.assertEqual(self.run_main(self.remote(), self.seeds(), ips=None), (1, {}))


class ListedUncoveredTest(unittest.TestCase):
    """Spec 71 D9: a research-listed list must be fetched from a URL PRIVATE_HOSTS matches."""

    def test_a_listed_list_fetched_from_an_unmatched_url_is_refused(self):
        blob = "https://github.com/someone/lists/blob/main/a.m3u"
        research_lists = [{"url": blob, "reason": "nsfw"}, {"url": blob, "reason": "listed:zokerpunk"},
                          {"url": "https://lists.example/b.m3u", "reason": "-"}]
        raw = "https://raw.githubusercontent.com/someone/lists/main/a.m3u"
        pulls = [{"url": blob, "fetched": raw, "rows": "3"},
                 {"url": blob, "fetched": "https://raw.githubusercontent.com/zokerpunk/a.m3u", "rows": "3"},
                 {"url": "https://lists.example/b.m3u", "fetched": "https://lists.example/b.m3u", "rows": "3"},
                 {"url": blob, "fetched": "-", "rows": "0"}]
        self.assertEqual(build_pool.listed_uncovered(pulls, research_lists), pulls[:1])


if __name__ == "__main__":
    unittest.main()

