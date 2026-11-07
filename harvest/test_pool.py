"""Unit tests for the list parsers, the channel join and the pool builder (Spec 60 H1b).
Run: python3 -m unittest discover -s harvest
"""
import base64
import io
import json
import socket
import sys
import tempfile
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
from channels import Channels, name_key, provider_id
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

    def test_state_does_not_leak_to_the_next_entry_and_images_are_skipped(self):
        rows = self.parse('#EXTINF:-1 tvg-id="A.us",A\n#EXTVLCOPT:http-user-agent=UA\nhttps://a.example/a.m3u8\n'
                          "https://b.example/b.m3u8\n#EXTINF:-1,Logo\nhttps://img.example/logo.png\n")
        self.assertEqual([(r["url"], r["tvg_id"], r["headers"]) for r in rows],
                         [("https://a.example/a.m3u8", "A.us", '{"User-Agent":"UA"}'), ("https://b.example/b.m3u8", "", "-")])


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
            data = {"x": data}
        self.assertEqual(len(list(lists.parse_json_list(data, SOURCE))), 1)

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


class RoundOneTest(unittest.TestCase):
    """Fixes from H1b red-team review round 1 (Spec 60)."""

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
        for category in ("XXX Movies", "Adult Channels", "18+", "news;Porn"):
            self.assertTrue(rules.nsfw_category(category), category)
        for category in ("Adult Swim", "general", "-"):
            self.assertFalse(rules.nsfw_category(category), category)

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
        panel = "http://panel.example:8080/get.php?username=u&password=p&type=m3u"
        self.assertEqual(lists.list_target(research(panel)), (None, "skip:credential"))

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

    def test_empty_header_values_are_dropped(self):
        self.assertEqual(lists.headers_cell([("Referer", " "), ("User-Agent", "UA")]), '{"User-Agent":"UA"}')


class RoundTwoTest(unittest.TestCase):
    """Fixes from H1b red-team review round 2 (Spec 60)."""

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
        self.assertEqual(verdict(copy("https://cdn.example.org/a.m3u8?start=12:30:45"), ALLOW).bucket, "public")

    def test_short_form_variants_and_refs_heads_duplicates(self):
        allow = Allowlist(["http://198.51.100.7:826/a/b/1"], parse_reviewed(""), vouches)
        for path in ("//u/p/120160", "/u/p/%31%32"):
            self.assertIsNone(allow.admit(f"http://198.51.100.7:826{path}"), path)
        self.assertEqual(lists.list_target(research("https://raw.githubusercontent.com/o/r/refs/heads/main/a.m3u")),
                         ("https://raw.githubusercontent.com/o/r/main/a.m3u", "static"))


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
        self.assertEqual(self.key("https://iptv.example/live/b.m3u8?token=2"), "BBC.uk")  # host+path
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

    def test_helpers(self):
        self.assertEqual(name_key("ＢＢＣ One (720p) [Not 24/7] FHD"), "bbc one")
        self.assertEqual(provider_id("https://i.mjh.nz/%2Er/maori.m3u8"), "mjh:maori")
        self.assertIsNone(provider_id("https://jmp2.uk/other"))


TEST_IP = "203.0.113.7"


class BuildPoolTest(unittest.TestCase):
    def run_main(self, remote: dict[str, bytes], seeds: dict[str, list[dict]], ips=(TEST_IP,)):
        """Runs main with fetches answered from `remote`; returns (exit code, files written)."""
        def fetch(url):
            if url not in remote:
                raise lists.FetchError("HTTP Error 404: Not Found")
            return lists.Fetched(url, url, remote[url])

        with tempfile.TemporaryDirectory() as d:
            public, private = Path(d) / "pub", Path(d) / "priv"
            for name, rows in seeds.items():
                path = (public if name.startswith("research-s") else private) / "seed" / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("\n".join(["\t".join(OUT_COLUMNS)] + ["\t".join(r[c] for c in OUT_COLUMNS)
                                                                      for r in rows]) + "\n", encoding="utf-8")
            lookup = (mock.patch.object(egress, "known_ips", side_effect=egress.LookupFailed("down")) if ips is None
                      else mock.patch.object(egress, "known_ips", return_value=set(ips)))
            with mock.patch.object(lists, "fetch", side_effect=fetch), lookup, \
                    mock.patch.object(sys, "argv", ["x", str(public), str(private)]), \
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
        return {"research-streams.tsv": [values], "research-sources.tsv": pick("public"),
                "research-private.tsv": pick("private"), "research-nsfw.tsv": pick("nsfw")}

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
        listed = research(SOURCE, reason="listed:bplaytv/")  # listed by its source page: the URL is clean
        self.assertEqual(self.buckets(self.seeds(listed), body)["https://iptv.example/live/x.m3u8"], "private.tsv")
        self.assertEqual(self.buckets(self.seeds(research(SOURCE, bucket="public", reason="reviewed-host")), body)
                         ["https://iptv.example/live/x.m3u8"], "streams.tsv")

    def test_a_research_stream_citing_an_nsfw_research_list_is_nsfw(self):
        seeds = self.seeds(research(SOURCE, bucket="nsfw", reason="nsfw"))
        seeds["research-streams.tsv"][0]["source_page"] = SOURCE
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

    def test_a_failed_required_source_fails_before_writing(self):
        remote = self.remote()
        del remote[lists.FAST_INDEXES["roku"][0]]
        self.assertEqual(self.run_main(remote, self.seeds()), (1, {}))
        self.assertEqual(self.run_main(self.remote(streams={"not": "a list"}), self.seeds()), (1, {}))

    def test_the_egress_ip_in_a_public_row_fails_before_writing(self):
        url = "https://iptv.example/live/3405803783/a.m3u8"
        streams = STREAMS + [{"url": url, "channel": None, "feed": None, "title": "Leak"}]
        self.assertEqual(self.run_main(self.remote(streams=streams), self.seeds()), (1, {}))
        self.assertEqual(self.run_main(self.remote(), self.seeds(), ips=None), (1, {}))


if __name__ == "__main__":
    unittest.main()
