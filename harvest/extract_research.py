#!/usr/bin/env python3
"""Extracts the Spec 60 research runs' stream tables into seed files (Nuvio-Project Spec 60 H1a, D12).

Usage: extract_research.py [--streams streams.json] <public-repo> <private-repo> <research-run-dir> [...]

Each researcher report ends in a fenced ```tsv block with 11 columns (name, url, country, language, category,
kind, format, headers, geo_hint, source_page, notes). Rows with another column count are analysis tables and are
skipped and counted; a skipped line that holds a URL (any "scheme://") fails the run (exit 1). A block's first
line is dropped only when it is a header (its first cell is exactly "name"); otherwise it is read as data. Rows are
deduplicated by exact URL: the first row's data is kept, the most restrictive bucket of all its copies wins
(nsfw > private > public), and every report that recorded the URL is listed in seen_in. The allowlist
(allowlist.py) is built from iptv-org's streams.json (downloaded unless --streams names a local copy) and
reviewed-hosts.txt. Before anything is written, every public row is checked for this machine's egress IP
(egress.py); a hit or a failed lookup fails the run (exit 1) and no file is written. Outputs (plain TSV, values
verbatim, no escaping):
  <public-repo>/seed/research-streams.tsv     public bucket, kind=stream (and any other non-list kind)
  <public-repo>/seed/research-sources.tsv     public bucket, kind=list-endpoint or api
  <private-repo>/seed/research-private.tsv    private bucket, every kind, with its reason
  <private-repo>/seed/research-nsfw.tsv       nsfw bucket, every kind
"""
import argparse
import collections
import re
import sys
from pathlib import Path

import egress
from allowlist import Allowlist
from rules import LIST_KINDS, RANK, bucket, vouches

COLUMNS = ["name", "url", "country", "language", "category", "kind", "format", "headers", "geo_hint",
           "source_page", "notes"]
OUT_COLUMNS = COLUMNS + ["reason", "seen_in"]
TSV_BLOCK = re.compile(r"```tsv[ \t]*\n(.*?)```", re.DOTALL)
REPORT = re.compile(r"^\d\d-.*\.md$")
URL_IN_LINE = re.compile(r"[a-z][a-z0-9+.-]*://", re.IGNORECASE)
# R1 reports whose rows lost markdown escapes or percent-encoding during writing (R1 final report, parser notes).
RECHECK = {"2026-11-06-162030": ("31-", "36-", "38-")}


def rows_of(run_dir: Path, skipped: list[str], empty: list[str]):
    """Yields (row, where) for every 11-column table row; records skipped lines and reports with no table."""
    run = run_dir.name[:17]
    for report in sorted(p for p in run_dir.iterdir() if REPORT.match(p.name) and not p.name.startswith("00-")):
        recheck = report.name.startswith(RECHECK.get(run, ()))
        blocks = TSV_BLOCK.findall(report.read_text(encoding="utf-8"))
        if not blocks:
            empty.append(f"{run}/{report.name}")
        for block in blocks:
            lines = block.strip().split("\n")
            if lines and lines[0].split("\t")[0].strip().lower() == "name":
                lines = lines[1:]
            for line in lines:
                cells = line.split("\t")
                if len(cells) != len(COLUMNS):
                    if line.strip():
                        skipped.append(f"{run}/{report.name[:2]}: {line}")
                    continue
                row = dict(zip(COLUMNS, (c.strip() for c in cells)))
                row["kind"] = row["kind"].lower()
                if recheck:
                    row["notes"] = (row["notes"] + "; recheck: report text may have lost escapes").lstrip("; ")
                yield row, f"{run}/{report.name[:2]}"


def merge(rows, allow: Allowlist) -> dict[str, dict]:
    """Dedupes (row, where) pairs by URL; the most restrictive bucket of any copy wins, with its reason."""
    kept: dict[str, dict] = {}
    for row, where in rows:
        name, reason = bucket(row, allow)
        old = kept.get(row["url"])
        if old is None:
            kept[row["url"]] = {**row, "reason": reason, "seen_in": where, "_bucket": name}
            continue
        if where not in old["seen_in"].split(","):
            old["seen_in"] += "," + where
        if RANK[name] > RANK[old["_bucket"]]:
            old["_bucket"], old["reason"] = name, reason
    return kept


def tsv(rows: list[dict]) -> str:
    lines = ["\t".join(OUT_COLUMNS)]
    for r in rows:
        values = [r[c] for c in OUT_COLUMNS]
        if any("\t" in v or "\n" in v for v in values):  # cells come from tab-split lines; never expected
            raise ValueError(f"tab or newline in a value: {r['url']}")
        lines.append("\t".join(values))
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract the Spec 60 research tables into seed files.")
    parser.add_argument("--streams", type=Path, help="local copy of iptv-org's streams.json (default: download)")
    parser.add_argument("public", type=Path)
    parser.add_argument("private", type=Path)
    parser.add_argument("runs", type=Path, nargs="+")
    args = parser.parse_args()
    skipped: list[str] = []
    empty: list[str] = []
    pairs = [pair for run_dir in args.runs for pair in rows_of(run_dir, skipped, empty)]
    for name in empty:
        print(f"  no table: {name}")
    lost = [s for s in skipped if URL_IN_LINE.search(s)]
    if lost:
        for line in lost:
            print(f"  SKIPPED WITH A URL: {line[:200]}", file=sys.stderr)
        return 1
    kept = merge(pairs, Allowlist.load(args.streams, vouches))

    def pick(b: str, kinds: tuple[str, ...] | None = None) -> list[dict]:
        return [{k: v for k, v in r.items() if k != "_bucket"} for r in kept.values()
                if r["_bucket"] == b and (kinds is None or r["kind"] in kinds)]

    streams = [r for r in pick("public") if r["kind"] not in LIST_KINDS]
    sources = pick("public", LIST_KINDS)
    outputs = {args.public / "seed" / "research-streams.tsv": tsv(streams),
               args.public / "seed" / "research-sources.tsv": tsv(sources),
               args.private / "seed" / "research-private.tsv": tsv(pick("private")),
               args.private / "seed" / "research-nsfw.tsv": tsv(pick("nsfw"))}
    try:
        needles = [egress.Needles(ip) for ip in egress.known_ips()]
    except egress.LookupFailed as error:
        print(error, file=sys.stderr)
        return 1
    leaks = [r for r in streams + sources if egress.find("\t".join(r[c] for c in OUT_COLUMNS), needles)]
    if leaks:
        for r in leaks:  # the row's name and origin, never the URL that holds the IP
            print(f"  EGRESS IP in a public row: {r['name']} ({r['seen_in']})", file=sys.stderr)
        return 1
    for path, text in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    reasons = collections.Counter((r["_bucket"], r["reason"].split(":")[0]) for r in kept.values())
    print(f"rows read {len(pairs)}, unique URLs {len(kept)}: public streams {len(streams)}, public sources "
          f"{len(sources)}, private {len(pick('private'))}, nsfw {len(pick('nsfw'))}; skipped lines {len(skipped)}, "
          f"reports without a table {len(empty)}")
    for (b, reason), count in sorted(reasons.items()):
        print(f"  {b} {reason or '-'}: {count}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
