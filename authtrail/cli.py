"""Summarize common OpenSSH authentication events from a local log file."""
from __future__ import annotations
import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Iterable

FAIL_RE = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<source>\S+)")
SUCCESS_RE = re.compile(r"Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from (?P<source>\S+)")


def analyze(lines: Iterable[str], threshold: int = 5) -> dict:
    if threshold < 1:
        raise ValueError("threshold must be at least 1")
    failures: Counter[str] = Counter()
    successes = 0
    failure_events = 0
    for line in lines:
        failed = FAIL_RE.search(line)
        if failed:
            failures[failed.group("source")] += 1
            failure_events += 1
        elif SUCCESS_RE.search(line):
            successes += 1
    flagged = [
        {"source": source, "failed_attempts": count}
        for source, count in sorted(failures.items(), key=lambda item: (-item[1], item[0]))
        if count >= threshold
    ]
    return {
        "failure_events": failure_events,
        "successful_events": successes,
        "unique_failure_sources": len(failures),
        "threshold": threshold,
        "sources_at_or_above_threshold": flagged,
        "scope": "Local file summary only; counts do not establish malicious intent.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize OpenSSH auth events in a local log file.")
    parser.add_argument("logfile", type=Path, help="path to an authorized local log file")
    parser.add_argument("--threshold", type=int, default=5, help="failure count for review flag (default: 5)")
    args = parser.parse_args()
    try:
        with args.logfile.open(encoding="utf-8", errors="replace") as stream:
            result = analyze(stream, args.threshold)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
