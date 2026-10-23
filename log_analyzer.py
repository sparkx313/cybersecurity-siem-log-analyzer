"""Offline SSH authentication-log triage for text and gzip inputs."""

from __future__ import annotations

import argparse
import gzip
import ipaddress
import json
import os
import re
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

FAILED_RE = re.compile(
    r"sshd.*?\bFailed\s+(?P<method>password|publickey|keyboard-interactive/pam)\s+"
    r"for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>[^\s]+)\s+port\s+\d+",
    re.IGNORECASE,
)
ACCEPTED_RE = re.compile(
    r"sshd.*?\bAccepted\s+(?P<method>password|publickey|keyboard-interactive/pam)\s+"
    r"for\s+(?P<user>\S+)\s+from\s+(?P<ip>[^\s]+)\s+port\s+\d+",
    re.IGNORECASE,
)
class AnalysisError(ValueError):
    """Raised when a log file cannot be analyzed."""


def normalize_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip("[],")))
    except ValueError:
        return None


def analyze_file(path: Path, threshold: int = 5) -> dict:
    source = path.expanduser().resolve()
    if not source.is_file():
        raise AnalysisError(f"Input does not exist or is not a file: {source}")
    if threshold < 1:
        raise AnalysisError("Threshold must be a positive integer.")

    opener = gzip.open if source.suffix.lower() == ".gz" else open
    failed: Counter[str] = Counter()
    accepted: Counter[str] = Counter()
    failed_users: dict[str, Counter[str]] = defaultdict(Counter)
    lines_read = 0
    ignored_lines = 0

    try:
        with opener(source, "rt", encoding="utf-8", errors="replace") as log_file:
            for line in log_file:
                lines_read += 1
                match = FAILED_RE.search(line)
                if match:
                    address = normalize_ip(match.group("ip"))
                    if address:
                        failed[address] += 1
                        failed_users[address][match.group("user")] += 1
                    else:
                        ignored_lines += 1
                    continue

                match = ACCEPTED_RE.search(line)
                if match:
                    address = normalize_ip(match.group("ip"))
                    if address:
                        accepted[address] += 1
                    else:
                        ignored_lines += 1
                    continue

                ignored_lines += 1
    except (OSError, EOFError) as exc:
        raise AnalysisError(f"Could not read log file: {exc}") from exc

    sources = sorted(set(failed) | set(accepted))
    source_report = []
    for address in sources:
        source_report.append(
            {
                "source_ip": address,
                "failed_attempts": failed[address],
                "successful_attempts": accepted[address],
                "usernames_with_failed_attempts": dict(sorted(failed_users[address].items())),
                "alert": failed[address] >= threshold,
            }
        )
    alerts = [item for item in source_report if item["alert"]]
    return {
        "source_file": source.name,
        "lines_read": lines_read,
        "unmatched_or_invalid_lines": ignored_lines,
        "threshold": threshold,
        "failed_attempts": sum(failed.values()),
        "successful_attempts": sum(accepted.values()),
        "possible_brute_force_sources": alerts,
        "sources": source_report,
        "scope_note": (
            "Offline, pattern-based triage of common OpenSSH authentication messages. "
            "The threshold counts matching events across the entire supplied file; this is not a time-windowed detector "
            "and an alert is not proof of malicious activity."
        ),
    }


def render_text(report: dict) -> str:
    lines = [
        f"Log: {report['source_file']}",
        f"Lines read: {report['lines_read']}",
        f"Matched failed authentication events: {report['failed_attempts']}",
        f"Matched successful authentication events: {report['successful_attempts']}",
        f"Unmatched or invalid lines: {report['unmatched_or_invalid_lines']}",
        f"Alert threshold: {report['threshold']} failed events per IP in this file",
        "",
    ]
    if report["possible_brute_force_sources"]:
        lines.append("Possible repeated-failure sources:")
        for source in report["possible_brute_force_sources"]:
            users = ", ".join(source["usernames_with_failed_attempts"])
            user_text = f"; usernames: {users}" if users else ""
            lines.append(
                f"  {source['source_ip']}: {source['failed_attempts']} failures, "
                f"{source['successful_attempts']} successes{user_text}"
            )
    else:
        lines.append("No source exceeded the configured threshold.")
    lines.extend(["", report["scope_note"]])
    return "\n".join(lines)


def write_report(path: Path, content: str, source: Path) -> None:
    destination = path.expanduser().resolve()
    if destination == source.expanduser().resolve():
        raise AnalysisError("Report output must not overwrite the source log.")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n",
            prefix=f".{destination.name}.", suffix=".tmp",
            dir=destination.parent, delete=False,
        ) as output:
            temporary = Path(output.name)
            output.write(content)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
        temporary = None
    except OSError as exc:
        raise AnalysisError(f"Could not write report: {exc}") from exc
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Summarize common OpenSSH authentication events in a local log file."
    )
    parser.add_argument("--input", required=True, type=Path, help="OpenSSH text log or .gz file")
    parser.add_argument("--threshold", type=int, default=5, help="failed events from one IP to raise an alert")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--output", type=Path, help="optional text or JSON report file")
    parser.add_argument("--fail-on-alert", action="store_true", help="exit with status 1 when an IP exceeds the threshold")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        report = analyze_file(args.input, args.threshold)
        content = json.dumps(report, indent=2, ensure_ascii=False) if args.format == "json" else render_text(report)
        if args.output:
            write_report(args.output, content, args.input)
            print(f"Report saved to {args.output.expanduser().resolve()}")
        else:
            print(content)
    except AnalysisError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    if args.fail_on_alert and report["possible_brute_force_sources"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
