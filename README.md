# Nuvio KE channels

The live TV channel list for [Nuvio KE](https://github.com/Arshad-Kamal/Nuvio-KE): public live TV streams from
around the world, checked on a schedule so the app only offers channels that are working.

Scope: anything [iptv-org](https://github.com/iptv-org/iptv) would list; streams iptv-org lists are included as it
lists them. A stream is published only when iptv-org lists it, its host already serves an iptv-org stream or a free
ad-supported (FAST) service, or its host has been reviewed (`harvest/reviewed-hosts.txt`). Streams that need a
subscriber login, adult channels, DRM streams, URLs made for one viewer (tokens, session links) unless iptv-org lists
that exact URL, and hosts the research named as pay-channel restreams or proxies are not published.

## Files

- `seed/research-streams.tsv`: candidate streams found by research (not yet checked).
- `seed/research-sources.tsv`: lists and APIs to pull candidates from.
- `harvest/`: the scripts that build the candidate pool. Tests: `python3 -m unittest discover -s harvest`.
- `harvest/reviewed-hosts.txt`: hosts reviewed for publication.

The checked list the app downloads comes later.

## Takedown requests

If you own a channel listed here and want it removed, open an issue with the channel name; it will be removed
and kept off the list.
