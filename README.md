# Nuvio KE channels

The live TV channel list for [Nuvio KE](https://github.com/Arshad-Kamal/Nuvio-KE): public live TV streams from
around the world, checked on a schedule so the app only offers channels that are working.

Scope: anything [iptv-org](https://github.com/iptv-org/iptv) would list; streams iptv-org lists are included as it
lists them. A stream is published only when iptv-org lists it, its host already serves an iptv-org stream or a free
ad-supported (FAST) service, or its host has been reviewed (`harvest/reviewed-hosts.txt`). Streams that need a
subscriber login, adult channels, DRM streams, URLs made for one viewer (tokens, session links) unless iptv-org lists
that exact URL, and hosts the research named as pay-channel restreams or proxies are not published. A URL with a query
string (`?...`), `;` parameters or a Kodi `|` suffix is published only when iptv-org lists that exact URL.

## Files

- `pool/streams.tsv`: the candidate pool (not yet checked): iptv-org's streams, the FAST services (Pluto TV,
  Samsung TV Plus, Roku, Plex) and every list the research found, one row per URL. `channel` groups the URLs of one
  channel (an iptv-org channel id, or `<service>:<id>` for a FAST channel iptv-org lacks); `headers` is a JSON object
  of the Referer / User-Agent / Origin a stream needs (research notes that are not such headers stay in `notes`). Built by
  `python3 harvest/build_pool.py <this repo> <private repo>`.
- `harvest/`: the scripts that build the candidate pool. Tests: `python3 -m unittest discover -s harvest`.
- `harvest/reviewed-hosts.txt`: hosts reviewed for publication.
- `monitor/state.tsv`: what the monitor (`harvest/monitor.py`, run twice a day by `.github/workflows/monitor.yml` on a
  GitHub runner, at times that move 3 hours each day) last found for each stream it checks, one row per URL. `state`:
  `alive`; `suspect` (one failed check); `down` (two); `gone` (failing for 14 days with a last answer of 404/410, an
  unknown host or a FAST id its service dropped, or 30 days of any failure; twice as long for channels iptv-org marks
  Not 24/7); `blocked` (refused twice in a row from the runner, or on a stream's first check, which says nothing about
  other countries). `since`: the day the current run of results began; `class`: the last result; `slots`: the UTC
  3-hour slots (00-03 first) the stream has worked in since it was last gone. FAST channels are judged by their
  service's channel index, plus a sample of checks that catches an outage of the whole service. `monitor/cursor`:
  where the next run continues (each run has a time budget).

The checked list the app downloads comes later.

## Takedown requests

If you own a channel listed here and want it removed, open an issue with the channel name; it will be removed
and kept off the list.
