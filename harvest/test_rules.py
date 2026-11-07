"""Unit tests for the bucket rules, the allowlist, the egress check and the extractor.
Run: python3 -m unittest discover -s harvest

Test IPs are documentation addresses (RFC 5737): 203.0.113.7 = 3405803783 = 0xCB007107 (203*2^24 + 113*2^8 + 7);
its little-endian form 07 71 00 CB = 124846283.
"""
import base64
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

import egress
import extract_research
import rules
from allowlist import REVIEWED_HOSTS, Allowlist, iptv_org_urls, parse_reviewed
from extract_research import COLUMNS, OUT_COLUMNS, tsv
from rules import bucket, verdict, vouches

IPTV_ORG = [
    "https://iptv.example/listed.m3u8",
    "https://cdn.example.org/live/other.m3u8",
    "https://raw.githubusercontent.com/someowner/lists/main/a.m3u8",
    "https://tinyurl.com/abc123",
    "http://198.51.100.9:8000/play/a01",
    "https://radio-proxy.example.net/a.m3u8",
    "https://iptv.example/signed.m3u8?token=abc",
    "https://rumble.com/live/abc",
    "http://panel.example:8080/live/u1/p1/1.ts",  # a credential URL iptv-org lists: it vouches for nothing
    "https://s3-us-west-2.amazonaws.com/bucket-a/live.m3u8",
]
# Hosts the deny-rule tests expect to stay public, reviewed so the allowlist admits them.
REVIEWED = """
x.example
racingvic-i.akamaized.net
cloud2.streaminglivehd.com:2020
www.stvr.sk
rtmp.apa.tv
news.example.org
102.129.84.200
145.159.95.10
ridsys.info
x-m3u.surge.sh
turnerlive.warnermediacdn.com
raw.githubusercontent.com/iptv-org   # owner prefix
"""
ALLOW = Allowlist(IPTV_ORG, parse_reviewed(REVIEWED), vouches)
TEST_IP = "203.0.113.7"


def b(url, name="Channel", fmt="hls", notes="-", kind="stream", category="general", source=None):
    """Buckets one row; by default the row was recorded directly (its source page is its own URL)."""
    return bucket(dict(name=name, url=url, format=fmt, notes=notes, kind=kind, category=category, headers="-",
                       source_page=url if source is None else source), ALLOW)


class BucketTest(unittest.TestCase):
    def test_credentials_are_private(self):
        for url in ("http://80.79.6.221:25461/smash/public/16",
                    "http://host.example:8080/live/user1/pass1/1234.ts",
                    "http://host.example/movie/user1/pass1/99.mkv",
                    "http://host.example/get.php?username=a&password=b&type=m3u",
                    "http://host.example/stream.m3u8?user=a&pass=b",
                    "http://admin:secret@cdn.example.com/x.m3u8",
                    "https://epg.provider.plex.tv/library/parts/x.m3u8?X-Plex-Token=abc",
                    "http://portal.example/c/?mac=00:1A:79:00:00:01",
                    "http://115.42.65.142:9981/stream/channelid/322092446",
                    "http://103.172.29.30:9991/stream/channel/a23a4ab90fe7569ced31e455b752ab51"):  # any port
            self.assertEqual(b(url), ("private", "credential"), url)

    def test_official_cdn_paths_are_not_credentials(self):
        for url in ("https://cdn.example.org/live/tv8/stream/playlist.m3u8",
                    "https://racingvic-i.akamaized.net/hls/live/598695/racingvic/1500.m3u8",  # Akamai bitrate
                    "https://cloud2.streaminglivehd.com:2020/hls/8036/8036.m3u8",
                    "https://www.stvr.sk/json/live5f.json?c=1&b=mozilla&p=win&f=0&d=1",  # p= is not a password
                    "https://rtmp.apa.tv/@pagroup!23.m3u8",  # "@" in the path, not userinfo
                    "https://news.example.org/widget.php?id=4"):  # not get.php
            # A query sends the row private under D15, but past every deny rule.
            self.assertIn(b(url)[1], ("iptv-org-host", "reviewed-host", "unreviewed-query"), url)

    def test_listed_hosts_are_private(self):
        self.assertEqual(b("https://mini.allinonereborn.fun/tata.php?id=1")[0], "private")
        self.assertEqual(b("http://102.129.84.20:8000/play/a01h"), ("private", "listed:102.129.84.20"))
        for host in ("ythls.armelin.one", "ythlsgo.onrender.com", "ythls-v2.onrender.com"):
            self.assertEqual(b(f"https://{host}/channel/x.m3u8"), ("private", "listed:ythls*"), host)
        self.assertEqual(b("https://raw.githubusercontent.com/saeidrahmanbd/BDIX-IPTV/main/IPTV-Playlist.m3u",
                           kind="list-endpoint"), ("private", "listed:saeidrahmanbd/bdix"))

    def test_listed_hosts_match_with_boundaries(self):
        for url in ("http://102.129.84.200/live.m3u8", "http://145.159.95.10/a.m3u8",
                    "https://ridsys.info/a.m3u8", "https://x-m3u.surge.sh/list.m3u"):
            self.assertEqual(b(url)[0], "public", url)

    def test_nsfw_is_its_own_bucket_and_wins_over_private(self):
        self.assertEqual(b("http://80.79.6.221:25461/a/b/1", name="Erotica"), ("nsfw", "nsfw"))
        self.assertEqual(b("https://iptv-org.github.io/iptv/categories/xxx.m3u", kind="list-endpoint"),
                         ("nsfw", "nsfw"))
        self.assertEqual(b("https://cdn.example.org/a.m3u8", name="XXXTV HD"), ("nsfw", "nsfw"))
        self.assertEqual(b("https://cdn.example.org/a.m3u8", name="Dorcel TV"), ("nsfw", "nsfw"))
        self.assertEqual(b("https://cdn.example.org/a.m3u8", category="XXX"), ("nsfw", "nsfw"))
        self.assertEqual(b("https://cdn.example.org/a.m3u8", category="movies;xxx"), ("nsfw", "nsfw"))

    def test_adult_swim_is_not_nsfw(self):
        self.assertEqual(b("https://turnerlive.warnermediacdn.com/hls/live/1/aseast/x.m3u8",
                           name="Adult Swim (East)", category="entertainment")[0], "public")

    def test_drm_streams_are_private_but_not_drm_free_ones(self):
        self.assertEqual(b("https://x.example/a.mpd", fmt="dash", notes="Widevine license"), ("private", "drm"))
        self.assertEqual(b("https://x.example/a.m3u8", notes="free-to-air, no DRM")[0], "public")
        self.assertEqual(b("https://x.example/a.m3u8", notes="DRM-free")[0], "public")
        self.assertEqual(b("https://x.example/a.m3u8", notes="Widevine", kind="other"), ("private", "drm"))

    def test_a_negated_mention_does_not_cancel_a_positive_one(self):
        # ORF 1 (research-streams.tsv before the fix): FairPlay DRM, the note also names a non-DRM variant.
        self.assertEqual(b("https://orf1.mdn.ors.at/orf/orf1/drmqxa/manifest.m3u8", name="ORF 1 (DRM)",
                           notes="FairPlay SAMPLE-AES DRM; non-DRM qxa returns 403"), ("private", "drm"))
        self.assertEqual(b("https://x.example/a.m3u8", name="Channel (DRM)"), ("private", "drm"))
        for notes in ("not DRM-free since 2025", "isn't DRM-free", "isn\u2019t DRM-free", "no longer DRM-free",
                      "never DRM free"):
            self.assertEqual(b("https://x.example/a.m3u8", notes=notes), ("private", "drm"), notes)

    def test_drm_notes_on_a_list_do_not_move_the_list(self):
        self.assertEqual(b("https://x.example/list.m3u", notes="drop KODIPROP DRM entries", kind="list-endpoint"),
                         ("public", "reviewed-host"))

    def test_non_http_and_schemeless_are_private_with_their_own_reasons(self):
        self.assertEqual(b("rtmp://live.example/app/stream"), ("private", "non-http"))
        self.assertEqual(b("gizmo.rakuten.tv/v3/live_channels", kind="api"), ("private", "no-scheme"))


class MintedTest(unittest.TestCase):
    def test_a_path_token_is_minted_even_on_an_admitted_host(self):
        # The shape of TVP's tokenizer output, which embedded the requester's IP as a decimal uint32.
        url = "https://cdn.example.org/token/video/live/51656539/20261106/3405803783/NT7bu06S/index.m3u8"
        self.assertEqual(b(url), ("private", "minted"))

    def test_query_tokens_and_jwts_are_minted(self):
        for url in ("https://x.example/a.m3u8?hdnts=exp=1~acl=/*~hmac=ab",
                    "https://x.example/a/playlist.m3u8?wmsAuthSign=c2VydmVyX3RpbWU9",
                    "https://x.example/a.m3u8?token=abc",
                    "https://x.example/a.m3u8?a=1&sid=76arxwhpzqio",
                    "https://x.example/sec2(3Jqd2eRQ)/live.m3u8",
                    "https://x.example/x/chunklist_w1312427303_DVR.m3u8",
                    "https://x.example/v1/session/c6f323e65336/master.m3u8",
                    "https://x.example/live.m3u8?k=eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3OTM5fQ.sig",
                    "https://x.example/hls/1/playlist.m3u8?id=1&sign=0f1e2d",
                    "https://x.example/live/playlist.m3u8?wowzasessionid=12345",
                    "https://x.example/live/playlist.m3u8;jsessionid=ABC",
                    "https://x.example/a.m3u8?X-Amz-Algorithm=A&X-Amz-Signature=ab",
                    "https://x.example/master.m3u8?dai-sr=1&api-key=0A75",
                    "https://x.example/live/expire/1793970002/ip/x/index.m3u8",
                    "https://x.example/live/a.m3u8?wsSecret=ab12&wsTime=6a2b",  # Wangsu
                    "https://x.example/live/a.m3u8?txSecret=ab12&txTime=6a2b",  # Tencent
                    "https://x.example/live/a.m3u8?wowzatokenhash=ab12",
                    "https://x.example/live/a.m3u8?session_token=ab12",
                    "https://x.example/live/a.m3u8?authToken=ab12",
                    "https://x.example/v1/master/abc/cfg/index.m3u8?aws.sessionId=0d3e",  # MediaTailor
                    "https://x.example/v1/manifest/9f8e7d/cfg/0d3e2a1b-1111-2222-3333-444455556666/0.m3u8",
                    "https://x.example/linear/hls/pa/event/K/stream/0d3e2a1b-1111-2222-3333-444455556666:CHS/m.m3u8",
                    "https://x.example/live/a.m3u8?e=1793970002&h=0f1e2d",  # MBC
                    "https://x.example/live/a.m3u8?h=0f1e2d&e=1793970002",  # Limelight order
                    "https://x.example/live/a.m3u8?access-token=ab12",
                    "https://x.example/live/a.m3u8?session=4f2a9c1e",
                    "https://x.example/live/a.m3u8?__gda__=1793970002_ab12",
                    "https://x.example/live/a.m3u8?ec_secure=ab12",
                    "https://x.example/live/a.m3u8?hmac=ab12",
                    "https://x.example/live/a.m3u8?__hdnea__=ab12",
                    "https://x.example/live/a.m3u8?st=ab12&e=1793970002",  # nginx secure_link
                    "https://x.example/live/a.m3u8?secure=ab12",
                    "https://x.example/live/a.m3u8?nonce=ab12"):
            self.assertEqual(b(url), ("private", "minted"), url)

    def test_notes_mark_a_stream_minted_but_not_a_list(self):
        for notes in ("IP-bound, 2 h", "session-signed (expiring)", "ad macro param may expire", "session chunklist"):
            self.assertEqual(b("https://x.example/a.m3u8", notes=notes), ("private", "minted"), notes)
        self.assertEqual(b("https://x.example/list.m3u", notes="entries are IP-bound", kind="list-endpoint"),
                         ("public", "reviewed-host"))

    def test_a_stream_read_from_a_dynamic_source_is_minted(self):
        for source in ("https://services.radio-canada.ca/media/validation/v2/?appCode=medianetlive&idMedia=1",
                       "https://api.tvp.pl/tokenizer/token/51656539",
                       "https://www.cbsnews.com/video/xhr/collection/component/live-channels/",  # round-2 miss
                       "https://geo.spilari.example/channel/ruv",
                       "https://addon.example/stream/tv/1tv.json",
                       "https://x.example/live-tv",  # a broadcaster page
                       "https://jmp2.uk/plu-5ad8d3a31b95267e225e4e09.m3u8",  # a redirector
                       "https://i.mjh.nz/.r/10-nsw.m3u8",
                       "https://i.mjh.nz/%2Er/10-nsw.m3u8",  # the same redirector, encoded
                       "https://raw.githubusercontent.com/o/r/main/x.m3u (resolved via https://api.example/1)",
                       "https://raw.githubusercontent.com/o/r/main/x.m3u (Libya list)",  # free text after the URL
                       "https://raw.githubusercontent.com/o/r/main/x.m3u,https://api.example/1",  # two URLs
                       "https://lists.example/tv.m3u8",  # a playlist on a web host that could build it per request
                       "https://evil.example\\.github.io/list.m3u",  # read by other parsers as evil.example
                       "-"):
            self.assertEqual(b("https://x.example/a.m3u8", source=source), ("private", "minted"), source)

    def test_static_sources_and_direct_records_are_not_minted(self):
        for source in ("https://raw.githubusercontent.com/someone/lists/main/korea.json",
                       "https://api.github.com/repos/someone/lists/contents/",
                       "https://teleonline.github.io/tv/es.html",
                       "https://i.mjh.nz/PlutoTV/.channels.json",
                       "https://pastebin.com/raw/abc"):
            self.assertEqual(b("https://x.example/a.m3u8", source=source), ("public", "reviewed-host"), source)
        # Recorded directly, even when the URL itself looks like an API.
        self.assertEqual(b("https://x.example/api/v1/live.m3u8"), ("public", "reviewed-host"))
        # An API row is a recipe source, not a minted stream.
        self.assertEqual(b("https://x.example/v1/channels", kind="api", source="https://x.example/live-tv"),
                         ("public", "reviewed-host"))

    def test_tokens_and_credentials_in_other_published_cells_are_private(self):
        self.assertEqual(b("https://x.example/a.m3u8", notes="302 to https://cdn.example/a.m3u8?hdnts=exp=1~hmac=ab"),
                         ("private", "minted"))
        self.assertEqual(b("https://x.example/list.m3u", kind="list-endpoint",
                           source="https://x.example/list.m3u?token=ab12"), ("private", "minted"))
        self.assertEqual(b("https://x.example/a.m3u8", notes="panel http://h.example/get.php?username=a&password=b"),
                         ("private", "credential"))
        # A list's notes describe its contents, not the list URL.
        self.assertEqual(b("https://x.example/list.m3u", kind="api", notes="contains :25461 entries -> scope filter"),
                         ("public", "reviewed-host"))
        self.assertEqual(bucket(dict(name="C", url="https://x.example/a.m3u8", format="hls", notes="-", kind="stream",
                                     category="general", source_page="https://x.example/a.m3u8",
                                     headers="Authorization Bearer eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjF9.sig"), ALLOW),
                         ("private", "minted"))

    def test_a_row_from_an_nsfw_list_is_nsfw(self):
        self.assertEqual(b("https://iptv.example/listed.m3u8", name="Venus",
                           source="https://iptv-org.github.io/iptv/categories/xxx.m3u"), ("nsfw", "nsfw"))

    def test_a_row_copied_from_a_listed_pirate_list_is_private(self):
        self.assertEqual(b("https://cdn.example.org/live/x.m3u8",
                           source="https://raw.githubusercontent.com/zokerpunk/tv/main/id.m3u"),
                         ("private", "listed:zokerpunk"))

    def test_an_exact_iptv_org_url_is_not_minted_by_us(self):
        self.assertEqual(b("https://iptv.example/signed.m3u8?token=abc"), ("public", "iptv-org-url"))
        self.assertEqual(b("https://iptv.example/listed.m3u8", source="https://api.example/v1/live"),
                         ("public", "iptv-org-url"))


class AllowlistTest(unittest.TestCase):
    def test_each_criterion_admits(self):
        self.assertEqual(b("https://iptv.example/listed.m3u8"), ("public", "iptv-org-url"))
        self.assertEqual(b("https://cdn.example.org/live/new.m3u8"), ("public", "iptv-org-host"))
        for url in ("https://jmp2.uk/plu-5ad8d3a31b95267e225e4e09.m3u8", "https://i.mjh.nz/.r/abc.m3u8",
                    "https://amg00276-amg00276c17-samsung-gb-3791.playouts.now.amagi.tv/playlist.m3u8",
                    "https://reuters-reutersnow-1-eu.rakuten.wurl.tv/playlist.m3u8",
                    "https://aka-live491.delivery.roku.com/31ffe9d4/live.m3u"):
            self.assertEqual(b(url), ("public", "fast-host"), url)
        self.assertEqual(b("https://x.example/new.m3u8"), ("public", "reviewed-host"))

    def test_hosts_nobody_vouched_for_are_private(self):
        # The three proxies review round 3 found public under the deny-list.
        for url in ("https://q-s-l4n3sh4d0w.onrender.com/iptv-query?streaming-ip=a.b&id=1",
                    "https://iptv-all.lanesh4d0w.codes/live/x.m3u8",
                    "https://cors-proxy.cooks.fyi/https://pay.example/x.m3u8",
                    "https://unknown.example/live.m3u8",
                    "https://www.youtube.com/watch?v=abc"):
            self.assertEqual(b(url), ("private", "unreviewed-host"), url)

    def test_a_url_the_deny_rules_reject_vouches_for_no_host(self):
        # Xtream short form on the panel iptv-org listed a credential URL from: no generic pattern catches it.
        self.assertEqual(b("http://panel.example:8080/u2/p2/77.ts"), ("private", "unreviewed-host"))

    def test_urls_another_parser_reads_differently_are_not_host_admitted(self):
        for url in ("https://evil.example\\.pluto.tv/live.m3u8",  # OkHttp/WHATWG connect to evil.example
                    "https://raw.githubusercontent.com/iptv-org/../attacker/repo/main/x.m3u",
                    "https://raw.githubusercontent.com/iptv-org/%2e%2e/attacker/repo/main/x.m3u",
                    "https://raw.githubusercontent.com/iptv-org%2F..%2Fattacker/repo/main/x.m3u",
                    "https://cdn.example.org/live/%5c..%5cother.m3u8",
                    "https://\u043f\u0440.pluto.tv/live.m3u8"):  # a non-ASCII host
            self.assertEqual(b(url, kind="list-endpoint"), ("private", "unreviewed-host"), url)

    def test_path_style_storage_is_keyed_by_bucket(self):
        self.assertEqual(b("https://s3-us-west-2.amazonaws.com/bucket-a/other.m3u8"), ("public", "iptv-org-host"))
        self.assertEqual(b("https://s3-us-west-2.amazonaws.com/bucket-b/x.m3u8"), ("private", "unreviewed-host"))

    def test_ipv6_literal_keys_keep_the_port_apart(self):
        allow = Allowlist(["http://[2001:db8::1]:8000/a.m3u8"], parse_reviewed("[2001:db8::2]:9000/live"), vouches)
        self.assertEqual(allow.admit("http://[2001:db8::1]:8000/b.m3u8"), "iptv-org-host")
        self.assertIsNone(allow.admit("http://[2001:db8::1:8000]/b.m3u8"))
        self.assertEqual(allow.admit("http://[2001:db8::2]:9000/live/x.m3u8"), "reviewed-host")
        self.assertIsNone(allow.admit("http://[2001:db8::2:9000]/live/x.m3u8"))

    def test_the_port_is_part_of_the_host(self):
        self.assertEqual(b("http://198.51.100.9:8000/play/a02"), ("public", "iptv-org-host"))
        self.assertEqual(b("http://198.51.100.9:8080/play/a02"), ("private", "unreviewed-host"))
        self.assertEqual(b("https://cdn.example.org:443/live/x.m3u8"), ("public", "iptv-org-host"))

    def test_a_code_host_admits_only_the_listed_owner(self):
        self.assertEqual(b("https://raw.githubusercontent.com/SomeOwner/other/main/b.m3u", kind="list-endpoint"),
                         ("public", "iptv-org-host"))
        for url in ("https://raw.githubusercontent.com/otherowner/lists/main/a.m3u",
                    "https://raw.githubusercontent.com/someowner-fake/lists/main/a.m3u",
                    "https://raw.githubusercontent.com/"):
            self.assertEqual(b(url, kind="list-endpoint"), ("private", "unreviewed-host"), url)

    def test_open_hosts_proxies_and_embedded_urls_never_count_by_host(self):
        self.assertEqual(b("https://tinyurl.com/abc123"), ("public", "iptv-org-url"))
        for url in ("https://tinyurl.com/other",  # iptv-org lists one tinyurl link, not the host
                    "https://rumble.com/embedJS/u3/",  # nor one rumble channel
                    "https://radio-proxy.example.net/b.m3u8",  # iptv-org lists one URL on this proxy
                    "https://cdn.example.org/play?url=https://pay.example/x.m3u8",
                    "https://cdn.example.org/play?u=https%3A%2F%2Fpay.example%2Fx.m3u8",
                    "https://cdn.example.org/play?u=https%253A%252F%252Fpay.example%252Fx.m3u8",
                    "https://cdn.example.org/play?src=//pay.example/x.m3u8",
                    "https://cdn.example.org/p/aHR0cHM6Ly9wYXkuZXhhbXBsZS94Lm0zdTg/index.m3u8",
                    "https://cdn.example.org/p/WGh0dHBzOi8vcGF5LmV4YW1wbGU/index.m3u8",  # "Xhttps://pay.example"
                    "https://cdn.example.org/p/WFhodHRwczovL3BheS5leGFtcGxl/index.m3u8"):  # "XXhttps://..."
            self.assertEqual(b(url), ("private", "unreviewed-host"), url)

    def test_a_reviewed_prefix_matches_whole_segments(self):
        self.assertEqual(b("https://raw.githubusercontent.com/IPTV-org/iptv/master/streams/de.m3u",
                           kind="list-endpoint"), ("public", "reviewed-host"))
        self.assertEqual(b("https://raw.githubusercontent.com/iptv-org-mirror/iptv/master/de.m3u",
                           kind="list-endpoint"), ("private", "unreviewed-host"))

    def test_a_shared_host_review_needs_an_owner_path(self):
        for entry in ("raw.githubusercontent.com", "cdn.jsdelivr.net/gh", "bit.ly", "https://x.example",
                      "x.example extra", "x.example:443", "x.example:80/live", "s3.amazonaws.com", "x.example:ab",
                      "[2001:db8::1"):
            with self.assertRaises(ValueError, msg=entry):
                parse_reviewed(entry)
        self.assertEqual(parse_reviewed("bit.ly/abc  # one link\n\n# note"), [("bit.ly", ["abc"])])

    def test_the_reviewed_hosts_file_parses(self):
        self.assertTrue(parse_reviewed(REVIEWED_HOSTS.read_text(encoding="utf-8")))

    def test_iptv_org_urls_reads_a_local_copy(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "streams.json"
            path.write_text(json.dumps([{"url": "https://a.example/1.m3u8"}, {"url": None}, "junk"]),
                            encoding="utf-8")
            self.assertEqual(iptv_org_urls(path), ["https://a.example/1.m3u8"])


class EgressTest(unittest.TestCase):
    NEEDLES = [egress.Needles(TEST_IP)]

    def find(self, text):
        return egress.find(text, self.NEEDLES)

    def test_plain_forms(self):
        self.assertEqual(self.find("http://203.0.113.7/x"), ["dotted"])
        self.assertEqual(self.find("http://203.000.113.007/x"), ["dotted"])
        self.assertEqual(self.find("https://ip-203-0-113-7.example/x"), ["dotted"])
        self.assertEqual(self.find("/c/203_0_113_7/x"), ["dotted"])
        self.assertEqual(self.find("7.113.0.203.in-addr.arpa"), ["dotted-reversed"])
        self.assertEqual(self.find("/token/video/live/1/20261106/3405803783/sig"), ["decimal"])
        self.assertEqual(self.find("/x/CB007107/y"), ["decoded:raw", "hex"])
        self.assertEqual(self.find("client=::ffff:cb00:7107"), ["hex"])
        self.assertEqual(self.find("?ip=124846283"), ["decimal-le"])

    def test_url_encoded_forms(self):
        self.assertEqual(self.find("?ip=203%2E0%2E113%2E7"), ["dotted"])
        self.assertEqual(self.find("?ip=203%252E0%252E113%252E7"), ["dotted"])

    def test_base64_forms_at_any_alignment(self):
        payload = base64.urlsafe_b64encode(b'{"exp":1793970002,"ip":"203.0.113.7"}').decode().rstrip("=")
        self.assertIn("decoded:dotted", self.find(f"?token=eyJhbGciOiJIUzI1NiJ9.{payload}.sig"))
        for prefix in ("", "a", "ab", "abc"):
            self.assertIn("decoded:dotted", self.find(f"/live/{prefix}{payload}/index.m3u8"), prefix)
        packed = base64.b64encode(b"\x01\x02" + bytes([203, 0, 113, 7]) + b"\x09" * 9).decode()
        self.assertIn("decoded:raw", self.find(f"/k/{packed}/x"))

    def test_base64_payloads_ending_in_the_ip_and_short_runs(self):
        for payload in (b"ip=203.0.113.7", b"203.0.113.7"):  # 14 and 11 bytes: the IP sits in the unpadded tail
            encoded = base64.b64encode(payload).decode()
            self.assertIn("decoded:dotted", self.find(f"?t={encoded}"), payload)
            self.assertIn("decoded:dotted", self.find(f"?t={encoded.rstrip('=')}"), payload)
        self.assertIn("decoded:raw", self.find("?c=ywBxBw=="))  # the 4 raw bytes alone: a 6-character run

    def test_hex_and_padded_forms(self):
        self.assertIn("decoded:dotted", self.find("?d=3230332e302e3131332e37"))  # hex of the ASCII "203.0.113.7"
        self.assertIn("decoded:dotted", self.find("?d=a3230332e302e3131332e37"))  # at the other alignment
        self.assertEqual(self.find("/n/203000113007/x"), ["octets-padded"])
        self.assertEqual(self.find("/m/cb-00-71-07/x"), ["hex-octets"])
        # 203.0.1.7: low half 0x0107, written padded in expanded IPv6 text.
        self.assertEqual(egress.find("client=0:0:0:0:0:ffff:cb00:0107", [egress.Needles("203.0.1.7")]), ["hex"])

    def test_other_addresses_and_clean_text_do_not_hit(self):
        for text in ("http://203.0.113.70/x", "http://1203.0.113.7/x", "https://cdn.example.org/live/index.m3u8"):
            self.assertEqual(self.find(text), [], text)

    def test_known_ips_keeps_every_address_seen(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(egress, "STATE", Path(d) / "s" / "ips"):
            with mock.patch.object(egress, "lookup", return_value={TEST_IP}):
                self.assertEqual(egress.known_ips(), {TEST_IP})
            with mock.patch.object(egress, "lookup", return_value={"198.51.100.1"}):
                self.assertEqual(egress.known_ips(), {TEST_IP, "198.51.100.1"})

    def test_the_cli_fails_on_a_hit_without_printing_the_ip(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "a.tsv").write_text("ok\nhttps://x.example/3405803783/a.m3u8\n", encoding="utf-8")
            out = io.StringIO()
            with mock.patch.object(egress, "known_ips", return_value={TEST_IP}), \
                    mock.patch.object(sys, "argv", ["egress.py", d]), redirect_stdout(out), \
                    redirect_stderr(io.StringIO()):
                self.assertEqual(egress.main(), 1)
        self.assertIn("a.tsv:2: decimal", out.getvalue())
        self.assertNotIn("3405803783", out.getvalue())


def merge(pairs):
    return rules.merge((r, where, verdict(r, ALLOW)) for r, where in pairs)


def row(url, notes="-", name="Channel"):
    values = dict.fromkeys(COLUMNS, "-")
    values.update(name=name, url=url, kind="stream", format="hls", notes=notes, source_page=url)
    return values


class MergeTsvTest(unittest.TestCase):
    def test_one_url_lands_in_one_bucket_the_most_restrictive(self):
        url = "https://x.example/a.mpd"
        for order in ((row(url), row(url, notes="Widevine")), (row(url, notes="Widevine"), row(url))):
            kept = merge([(order[0], "r1/01"), (order[1], "r1/02")])
            self.assertEqual(len(kept), 1)
            self.assertEqual((kept[url]["_bucket"], kept[url]["reason"], kept[url]["seen_in"]),
                             ("private", "drm", "r1/01,r1/02"))

    def test_nsfw_outranks_private_for_one_url(self):
        url = "http://80.79.6.221:25461/a/b/1"
        kept = merge([(row(url), "r1/01"), (row(url, name="Erotica"), "r1/02")])
        self.assertEqual((kept[url]["_bucket"], kept[url]["reason"]), ("nsfw", "nsfw"))

    def test_tsv_refuses_a_tab(self):
        r = {**row("https://x.example/a.m3u8", notes="a\tb"), "reason": "", "seen_in": "r1/01"}
        with self.assertRaises(ValueError):
            tsv([r])

    def test_values_are_written_verbatim(self):
        url = 'https://boot.pluto.tv/v4/start?appName=web&appVersion=""&clientID=""'
        r = {**row(url, notes=r"est\_128", name='gratis "TV"'), "reason": "", "seen_in": "r1/01"}
        line = dict(zip(OUT_COLUMNS, tsv([r]).split("\n")[1].split("\t")))
        self.assertEqual((line["url"], line["notes"], line["name"]), (url, r"est\_128", 'gratis "TV"'))


def tsv_line(name, url):
    return "\t".join([name, url] + ["-"] * 3 + ["stream", "hls"] + ["-"] * 4)


class MainTest(unittest.TestCase):
    def run_main(self, tsv_block: str, listed: list[str], ips=(TEST_IP,)) -> tuple[int, dict[str, str]]:
        """Runs main on one report; returns its exit code and the files written (name -> text)."""
        with tempfile.TemporaryDirectory() as d:
            run = Path(d) / "2026-11-06-000000-test"
            run.mkdir()
            (run / "01-lane.md").write_text("# r\n\n```tsv\n" + tsv_block + "```\n", encoding="utf-8")
            streams = Path(d) / "streams.json"
            streams.write_text(json.dumps([{"url": u} for u in listed]), encoding="utf-8")
            argv = ["x", "--streams", str(streams), str(Path(d) / "pub"), str(Path(d) / "priv"), str(run)]
            lookup = (mock.patch.object(egress, "known_ips", side_effect=egress.LookupFailed("down")) if ips is None
                      else mock.patch.object(egress, "known_ips", return_value=set(ips)))
            with mock.patch.object(sys, "argv", argv), lookup, redirect_stdout(io.StringIO()), \
                    redirect_stderr(io.StringIO()):
                code = extract_research.main()
            written = {p.name: p.read_text(encoding="utf-8") for p in Path(d).glob("p*/seed/*.tsv")}
        return code, written

    def test_a_run_writes_all_four_seeds(self):
        code, written = self.run_main(tsv_line("A", "https://a.example/a.m3u8") + "\n"
                                      + tsv_line("B", "https://b.example/b.m3u8") + "\n",
                                      ["https://a.example/a.m3u8"])
        self.assertEqual(code, 0)
        self.assertEqual(sorted(written), ["research-nsfw.tsv", "research-private.tsv", "research-sources.tsv",
                                           "research-streams.tsv"])
        self.assertIn("https://a.example/a.m3u8\t", written["research-streams.tsv"])
        self.assertIn("https://b.example/b.m3u8\t", written["research-private.tsv"])

    def test_a_skipped_line_holding_a_url_fails_the_run_before_writing(self):
        good = tsv_line("A", "https://a.example/a.m3u8")
        code, written = self.run_main("\t".join(COLUMNS) + "\n" + good + "\nBad\trtmp://x.example/live\tthree\n",
                                      ["https://a.example/a.m3u8"])
        self.assertEqual((code, written), (1, {}))

    def test_a_block_without_a_header_keeps_its_first_row(self):
        for name in ("A", "Name of the channel"):  # a first row named "Name..." is data, not a header
            code, written = self.run_main(tsv_line(name, "https://a.example/a.m3u8") + "\n",
                                          ["https://a.example/a.m3u8"])
            self.assertEqual(code, 0)
            self.assertIn("https://a.example/a.m3u8", written["research-streams.tsv"], name)

    def test_the_egress_ip_in_a_public_row_fails_the_run_before_writing(self):
        url = "https://a.example/live/3405803783/a.m3u8"  # public: iptv-org lists this exact URL
        code, written = self.run_main(tsv_line("A", url) + "\n", [url])
        self.assertEqual((code, written), (1, {}))

    def test_a_failed_egress_lookup_fails_the_run_before_writing(self):
        code, written = self.run_main(tsv_line("A", "https://a.example/a.m3u8") + "\n",
                                      ["https://a.example/a.m3u8"], ips=None)
        self.assertEqual((code, written), (1, {}))

    def test_a_stream_citing_an_nsfw_research_list_in_another_spelling_is_nsfw(self):
        listed = "\t".join(["Erotica lists", "https://raw.githubusercontent.com/o/r/main/x.m3u"] + ["-"] * 3
                           + ["list-endpoint", "m3u"] + ["-"] * 4)
        cited = "\t".join(["S", "https://a.example/s.m3u8"] + ["-"] * 3 + ["stream", "hls", "-", "-",
                          "https://github.com/o/r/blob/refs/heads/main/x.m3u", "-"])
        code, written = self.run_main(listed + "\n" + cited + "\n", ["https://a.example/a.m3u8"])
        self.assertEqual(code, 0)
        self.assertIn("https://a.example/s.m3u8\t", written["research-nsfw.tsv"])
        self.assertNotIn("https://a.example/s.m3u8\t", written["research-streams.tsv"])


if __name__ == "__main__":
    unittest.main()
