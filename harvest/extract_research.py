#!/usr/bin/env python3
"""Extracts the Spec 60 research runs' stream tables into seed files (Nuvio-Project Spec 60 H1a, D12, D16).

Usage: extract_research.py [--streams streams.json] <private-repo> <research-run-dir> [...]

Each researcher report ends in a fenced ```tsv block with 11 columns (name, url, country, language, category,
kind, format, headers, geo_hint, source_page, notes). Rows with another column count are analysis tables and are
skipped and counted; a skipped line that holds a URL (any "scheme://") fails the run (exit 1). A block's first
line is dropped only when it is a header (its first cell is exactly "name"); otherwise it is read as data. A stream
row whose source page is a research list the research put in nsfw, or private as a listed pirate list, carries that
list's verdict (lists.cited_taint, as in build_pool). Rows are deduplicated by exact URL (rules.merge: the
highest-ranked copy wins, a copy private only for its own source or cells yields to a public copy), and every report
that recorded the URL is listed in seen_in. The allowlist (allowlist.py) is built from iptv-org's streams.json
(downloaded unless --streams names a local copy) and reviewed-hosts.txt. The seeds are inputs to build_pool.py, which
re-judges every row and alone publishes (D16: no seed file is public). Outputs (plain TSV, values verbatim):
  <private-repo>/seed/research-public.tsv     rows the rules would publish, every kind
  <private-repo>/seed/research-private.tsv    private bucket, every kind, with its reason
  <private-repo>/seed/research-nsfw.tsv       nsfw bucket, every kind
"""
import argparse
import collections
import re
import sys
from pathlib import Path

import lists
from allowlist import Allowlist
from rules import LIST_KINDS, merge, stricter, verdict, vouches

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


def tsv(rows: list[dict], columns: list[str] | None = None) -> str:
    columns = columns or OUT_COLUMNS
    lines = ["\t".join(columns)]
    for r in rows:
        values = [r[c] for c in columns]
        if any("\t" in v or "\n" in v for v in values):  # cells come from tab-split lines; never expected
            raise ValueError(f"tab or newline in a value: {r['url']}")
        lines.append("\t".join(values))
    return "\n".join(lines) + "\n"


def write_all(outputs: dict[Path, str]) -> None:
    """Writes every output only after all of them encode (an unencodable string fails before the first write)."""
    encoded = {path: text.encode("utf-8") for path, text in outputs.items()}
    for path, data in encoded.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract the Spec 60 research tables into seed files.")
    parser.add_argument("--streams", type=Path, help="local copy of iptv-org's streams.json (default: download)")
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
    allow = Allowlist.load(args.streams, vouches)
    judged = [(row, where, verdict(row, allow)) for row, where in pairs]
    # Two merges: a list's taint is its merged verdict (list_taint reads _bucket and reason), and the stream rows
    # citing it carry that taint into the second merge.
    taints = lists.list_taints(merge(c for c in judged if c[0]["kind"] in LIST_KINDS).values())
    kept = merge((row, where, stricter(found, lists.cited_taint(taints, row))) for row, where, found in judged)

    def pick(b: str) -> list[dict]:
        return [{k: v for k, v in r.items() if not k.startswith("_")} for r in kept.values() if r["_bucket"] == b]

    write_all({args.private / "seed" / f"research-{b}.tsv": tsv(pick(b)) for b in ("public", "private", "nsfw")})
    reasons = collections.Counter((r["_bucket"], r["reason"].split(":")[0]) for r in kept.values())
    print(f"rows read {len(pairs)}, unique URLs {len(kept)}: public {len(pick('public'))}, private "
          f"{len(pick('private'))}, nsfw {len(pick('nsfw'))}; skipped lines {len(skipped)}, reports without a table "
          f"{len(empty)}")
    for (b, reason), count in sorted(reasons.items()):
        print(f"  {b} {reason or '-'}: {count}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
