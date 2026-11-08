#!/usr/bin/env python3
"""Builds the candidate pool from every list endpoint (Nuvio-Project Spec 60 H1b).

Usage: build_pool.py <public-repo> <private-repo>

Inputs, in merge order: iptv-org's streams.json; the i.mjh.nz FAST indexes (lists.FAST_INDEXES); the research seeds'
stream rows (<private>/seed/research-{public,private,nsfw}.tsv, extract_research.py; their free-text headers read by
lists.headers_from_text, text not read so kept in notes); every research list endpoint that is a list file
(lists.list_target), fetched now, a list that fails to pull keeping the rows its last good pull gave (carry: pulls.tsv
says "carried"; Spec 71 M1.1: the rows and their monitor history survive the list's outage). Every copy is bucketed by
rules.verdict (a row of a list the research put in nsfw, or private as a listed pirate list, and a research stream row
citing such a list, also carries that list's verdict: lists.list_taints), copies are merged by exact URL (rules.merge),
then each row gets its channel key and the iptv-org blocklist/NSFW joins, and NSFW spreads to every URL holding a FAST
channel id an nsfw row's URL holds (channels.py). streams.tsv is the only public output (D16). Fetching iptv-org's API
(streams, channels, blocklist) or a FAST index failing fails the run (exit 1); a research list failing is recorded in
pulls.tsv. Before anything is written every public row is checked for this machine's egress IP (egress.py); a hit or a
failed lookup fails the run and nothing is written. A private repo that is the public checkout (swapped arguments) is
refused (extract_research.private_repo). Outputs (plain TSV, values verbatim):
  <public>/pool/streams.tsv     public candidate streams (extract_research.OUT_COLUMNS + channel)
  <private>/pool/private.tsv    private rows with their reason
  <private>/pool/nsfw.tsv       NSFW rows
  <private>/pool/pulls.tsv      every research list endpoint: what was fetched, its class and status, rows read
seen_in names origins: iptv-org, fast:<service>, research, lists:<number of list files>.
"""
import argparse
import collections
import concurrent.futures
import json
import sys
from dataclasses import dataclass
from pathlib import Path

import egress
import lists
from allowlist import REVIEWED_HOSTS, Allowlist, parse_reviewed, stream_urls
from channels import Channels, spread_nsfw
from extract_research import COLUMNS, OUT_COLUMNS, SEED_BUCKETS, private_repo, seed_path, tsv, write_all
from rules import LIST_KINDS, Verdict, listed_source, merge, stricter, verdict, vouches

POOL_COLUMNS = OUT_COLUMNS + ["channel"]
PULL_COLUMNS = ["url", "fetched", "class", "status", "rows"]
IPTV_ORG_JOINS = ("channels.json", "blocklist.json")
FETCH_WORKERS = 8
FAILED = "error"  # a pulls.tsv status prefix: the list could not be fetched


@dataclass
class Previous:
    """What the last run wrote: pull records by research URL, and the pool rows of the lists it pulled by source page
    (each with "_floor", the verdict its file gave it)."""
    records: dict[str, dict[str, str]]
    rows: dict[str, list[dict[str, str]]]


def pool_files(public: Path, private: Path) -> dict[str, Path]:
    return {"public": public / "pool" / "streams.tsv", "private": private / "pool" / "private.tsv",
            "nsfw": private / "pool" / "nsfw.tsv", "pulls": private / "pool" / "pulls.tsv"}


def read_tsv(path: Path) -> list[dict[str, str]]:
    """Rows of a file written by extract_research.tsv (header line, tab-separated, verbatim)."""
    lines = path.read_text(encoding="utf-8").split("\n")
    header = lines[0].split("\t")
    return [dict(zip(header, line.split("\t"))) for line in lines[1:] if line]


def fetch_required() -> dict[str, bytes]:
    """iptv-org's API files and the FAST indexes; raises lists.FetchError when any fails."""
    urls = [lists.IPTV_ORG_STREAMS] + [lists.IPTV_ORG_API + name for name in IPTV_ORG_JOINS] + [
        source for source, _ in lists.FAST_INDEXES.values()]
    with concurrent.futures.ThreadPoolExecutor(FETCH_WORKERS) as pool:
        return {url: fetched.body for url, fetched in zip(urls, pool.map(lists.fetch, urls))}


def _pull(target: tuple[dict, str | None, str]) -> tuple[dict, list[dict[str, str]]]:
    """Fetches and parses one research list endpoint: (pulls.tsv row, rows read)."""
    research, url, kind = target
    record = {"url": research["url"], "fetched": url or "-", "class": kind, "status": "-", "rows": "0"}
    if url is None:
        return record, []
    try:
        fetched = lists.fetch(url)
    except lists.FetchError as error:
        record["status"] = lists.cell(f"{FAILED}: {error}")
        return record, []
    record["fetched"] = fetched.final_url
    found, rows = lists.parse_list(fetched, m3u_only=kind == "other-host")
    record.update(status=found, rows=str(len(rows)))
    return record, rows


def previous_run(public: Path, private: Path) -> Previous:
    """The last run's outputs (Previous); empty before the first run."""
    files = pool_files(public, private)
    records: dict[str, dict[str, str]] = {}
    for record in read_tsv(files["pulls"]) if files["pulls"].exists() else []:
        if record["fetched"] != "-":  # the fetched record of a URL, not a later skip:duplicate one
            records.setdefault(record["url"], record)
    sources = {r["fetched"] for r in records.values() if r["rows"] != "0"}
    rows: dict[str, list[dict[str, str]]] = collections.defaultdict(list)
    for name in ("public", "private", "nsfw"):
        for row in read_tsv(files[name]) if files[name].exists() else []:
            # a list's own rows only: a research row citing the list lives on through the seeds
            if row["source_page"] in sources and "lists:" in row["seen_in"]:
                row["_floor"] = _floor(name, row["reason"])
                rows[row["source_page"]].append(row)
    return Previous(records, dict(rows))


def _floor(file: str, reason: str) -> Verdict | None:
    """The least strict verdict a carried row may get: the one its previous file gave it (none for public)."""
    return {"public": None, "nsfw": Verdict("nsfw", "nsfw")}.get(file, Verdict("private", reason))


def carry(record: dict, rows: list[dict[str, str]], previous: Previous) -> tuple[dict, list[dict[str, str]]]:
    """A list that failed to pull keeps the rows its last good pull gave: those whose source page is the URL that pull
    fetched (a row another source won stays through that source). They are re-judged like fresh rows, never less
    strictly than last time (_floor). The old channel key comes along as a tvg-id, so a join iptv-org or the owner
    adds during the outage still reaches the row (keys written since Spec 71 M1.1 are no query-path guesses)."""
    last = previous.records.get(record["url"])
    if not record["status"].startswith(FAILED) or last is None:
        return record, rows
    kept = [{**{c: r[c] for c in COLUMNS}, "tvg_id": r["channel"], "_floor": r["_floor"]}
            for r in previous.rows.get(last["fetched"], [])]
    if not kept:
        return record, rows
    return {**record, "fetched": last["fetched"], "status": lists.cell(f"carried: {record['status']}"),
            "rows": str(len(kept))}, kept


def pull_lists(research_lists: list[dict], taints: dict[str, Verdict | None], previous: Previous) \
        -> tuple[list[dict], list[tuple[list[dict[str, str]], Verdict | None]]]:
    """pulls.tsv rows (one per research row, in research order) and, per fetched list, its rows (or the rows carried
    from the last run when it failed) and taint (taints: lists.list_taints of the same rows). Research rows naming the
    same file are fetched once; the taint is already the strictest of all of them."""
    targets, fetching = [], set()
    for research in research_lists:
        url, kind = lists.list_target(research)
        if url in fetching:
            url, kind = None, "skip:duplicate"
        elif url is not None:
            fetching.add(url)
        targets.append((research, url, kind))
    with concurrent.futures.ThreadPoolExecutor(FETCH_WORKERS) as pool:
        results = [carry(record, rows, previous) for record, rows in pool.map(_pull, targets)]
    pulled = [(rows, taints.get(url)) for (_, url, _), (_, rows) in zip(targets, results) if url is not None]
    return [record for record, _ in results], pulled


def listed_uncovered(pulls: list[dict], taints: dict[str, Verdict | None]) -> list[dict]:
    """Pull records of lists the research marks listed whose fetched URL no PRIVATE_HOSTS entry matches. Their rows
    would carry the listed taint only as a copy-only verdict, which a stream-level private verdict (unreviewed-host)
    outranks, so no pool cell would keep the channel monitor from fetching them (Spec 71 D9: the run is refused)."""
    return [record for record in pulls if record["fetched"] != "-" and record["rows"] != "0"
            and (taint := taints.get(lists.list_url(record["url"]))) is not None and taint.reason.startswith("listed:")
            and listed_source(record["fetched"]) is None]


def research_seeds(private: Path) -> list[dict[str, str]]:
    """Every research seed row, its bucket (the file it is in) under "_bucket"."""
    return [{**row, "_bucket": name} for name in SEED_BUCKETS for row in read_tsv(seed_path(private, name))]


def research_row(seed: dict[str, str]) -> dict[str, str]:
    """A research seed stream row as a pool copy: free-text headers read into the headers cell; text not read so is
    kept in notes ("headers: ..."), unless it names a login or session (the private seed keeps it)."""
    row = {c: seed[c] for c in COLUMNS}
    if row["headers"] not in ("", "-") and not row["headers"].startswith("{"):
        headers, whole = lists.headers_from_text(row["headers"])
        if not whole:
            note = ("headers: a login or session header (not published)" if lists.HEADER_SECRET.search(row["headers"])
                    else f"headers: {row['headers']}")
            row["notes"] = "; ".join(n for n in (row["notes"], note) if n not in ("", "-"))
        row["headers"] = headers
    return row


def seen_in(origins: str) -> str:
    tags = origins.split(",")
    named = [t for t in tags if not t.startswith("list:")]
    count = len(tags) - len(named)
    return ",".join(named + ([f"lists:{count}"] if count else []))


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the Spec 60 candidate pool from every list endpoint.")
    parser.add_argument("public", type=Path)
    parser.add_argument("private", type=private_repo)
    args = parser.parse_args()
    try:
        required = fetch_required()
        streams = json.loads(required[lists.IPTV_ORG_STREAMS])
        joins = [json.loads(required[lists.IPTV_ORG_API + name]) for name in IPTV_ORG_JOINS]
        indexes = {service: json.loads(required[source]) for service, (source, _) in lists.FAST_INDEXES.items()}
        fast = {service: list(lists.fast_rows(service, index)) for service, index in indexes.items()}
        iptv_org = stream_urls(streams)
        if not all(isinstance(data, list) for data in joins):
            raise ValueError("iptv-org API: expected JSON arrays")
    except (lists.FetchError, ValueError) as error:  # json.JSONDecodeError is a ValueError
        print(f"required source failed: {error}", file=sys.stderr)
        return 1
    allow = Allowlist(iptv_org, parse_reviewed(REVIEWED_HOSTS.read_text(encoding="utf-8")), vouches)
    seeds = research_seeds(args.private)
    research_lists = [row for row in seeds if row["kind"] in LIST_KINDS]
    taints = lists.list_taints(research_lists)
    pulls, pulled = pull_lists(research_lists, taints, previous_run(args.public, args.private))
    if uncovered := listed_uncovered(pulls, taints):
        print(f"refused: {len(uncovered)} research-listed list(s) fetched from a URL no rules.PRIVATE_HOSTS entry matches;"
              " add one (Spec 71 D9)", file=sys.stderr)
        return 1

    def copies():
        def tagged(rows, where, taint=None):
            return ((row, where, stricter(stricter(verdict(row, allow), taint), row.get("_floor"))) for row in rows)
        yield from tagged(lists.iptv_org_rows(streams), "iptv-org")
        for service, rows in fast.items():
            yield from tagged(rows, f"fast:{service}")
        for row in seeds:
            if row["kind"] not in LIST_KINDS:
                yield from tagged([research_row(row)], "research", lists.cited_taint(taints, row))
        for number, (rows, taint) in enumerate(pulled):
            yield from tagged(rows, f"list:{number}", taint)

    kept = merge(copies())
    joined = Channels(streams, *joins)
    for row in kept.values():
        joined.apply(row, row["_tvg_ids"], row["_names"])
        row["seen_in"] = seen_in(row["seen_in"])
    spread = spread_nsfw(kept.values())

    def pick(name: str) -> list[dict]:
        return [row for row in kept.values() if row["_bucket"] == name]

    public = pick("public")
    if not egress.publish_gate(public, POOL_COLUMNS):
        return 1
    files = pool_files(args.public, args.private)
    outputs = {files["public"]: tsv(public, POOL_COLUMNS), files["private"]: tsv(pick("private"), POOL_COLUMNS),
               files["nsfw"]: tsv(pick("nsfw"), POOL_COLUMNS), files["pulls"]: tsv(pulls, PULL_COLUMNS)}
    write_all(outputs)
    report(kept, pulls, fast, spread)
    return 0


def report(kept: dict[str, dict], pulls: list[dict], fast: dict[str, list], spread: tuple[int, int]) -> None:
    buckets = collections.Counter(row["_bucket"] for row in kept.values())
    reasons = collections.Counter((row["_bucket"], row["reason"].split(":")[0]) for row in kept.values())
    statuses = collections.Counter(p["status"].split(":")[0] if not p["class"].startswith("skip") else p["class"]
                                   for p in pulls)
    print(f"unique URLs {len(kept)}: public {buckets['public']}, private {buckets['private']}, nsfw {buckets['nsfw']}; "
          f"FAST rows {', '.join(f'{s} {len(r)}' for s, r in fast.items())}; channel keys "
          f"{sum(1 for r in kept.values() if r['channel'])}; NSFW spread: {spread[0]} FAST ids, {spread[1]} rows moved")
    print(f"research list endpoints {len(pulls)}: " + ", ".join(f"{k} {n}" for k, n in sorted(statuses.items())))
    for (name, reason), count in sorted(reasons.items()):
        print(f"  {name} {reason or '-'}: {count}")


if __name__ == "__main__":
    sys.exit(main())
