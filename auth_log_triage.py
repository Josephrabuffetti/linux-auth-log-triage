"""Review Linux SSH authentication logs for patterns worth investigating."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable


SYSLOG_PREFIX = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+sshd(?:-session)?(?:\[\d+\])?:\s+(?P<message>.*)$"
)
ISO_PREFIX = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"(?:Z|[+-]\d{2}:?\d{2})?)\s+.*?\bsshd(?:-session)?(?:\[\d+\])?:\s+(?P<message>.*)$"
)
FAILED = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from "
    r"(?P<ip>[0-9a-fA-F:.]+) port \d+\b"
)
ACCEPTED = re.compile(
    r"Accepted \S+ for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port \d+\b"
)


@dataclass(frozen=True)
class AuthEvent:
    timestamp: datetime
    username: str
    source_ip: str
    outcome: str


def _timestamp(value: str, year: int) -> datetime:
    if value[:3].isalpha():
        return datetime.strptime(f"{year} {value}", "%Y %b %d %H:%M:%S")
    normalized = value.replace("Z", "+00:00")
    if len(normalized) > 19 and normalized[19] == ".":
        # Keep fractional seconds from ISO timestamps without requiring a
        # particular number of digits.
        head, rest = normalized[:19], normalized[19:]
        if "+" in rest:
            fraction, offset = rest.split("+", 1)
            normalized = head + fraction[:7] + "+" + offset
        elif rest.count("-") > 1:
            fraction, offset = rest.rsplit("-", 1)
            normalized = head + fraction[:7] + "-" + offset
        else:
            normalized = head + rest[:7]
    if normalized.endswith(("+0000", "-0000")):
        normalized = normalized[:-5] + normalized[-5:-2] + ":" + normalized[-2:]
    if re.search(r"[+-]\d{4}$", normalized):
        normalized = normalized[:-5] + normalized[-5:-2] + ":" + normalized[-2:]
    try:
        return datetime.fromisoformat(normalized).replace(tzinfo=None)
    except ValueError as error:
        raise ValueError(f"unsupported timestamp: {value}") from error


def parse_line(line: str, year: int) -> AuthEvent | None:
    """Parse one OpenSSH accepted/failed-password record; ignore other lines."""
    match = SYSLOG_PREFIX.match(line) or ISO_PREFIX.match(line)
    if not match:
        return None
    message = match.group("message")
    result = FAILED.search(message)
    outcome = "failed"
    if result is None:
        result = ACCEPTED.search(message)
        outcome = "accepted"
    if result is None:
        return None
    try:
        address = str(ipaddress.ip_address(result.group("ip")))
        timestamp = _timestamp(match.group("timestamp"), year)
    except ValueError:
        return None
    return AuthEvent(timestamp, result.group("user"), address, outcome)


def parse_lines(lines: Iterable[str], year: int) -> tuple[list[AuthEvent], int]:
    events: list[AuthEvent] = []
    total = 0
    for line in lines:
        total += 1
        event = parse_line(line.rstrip("\n"), year)
        if event:
            events.append(event)
    events.sort(key=lambda event: event.timestamp)
    return events, total - len(events)


def _failed_burst(events: list[AuthEvent], threshold: int, window: timedelta) -> dict | None:
    failures = sorted((event for event in events if event.outcome == "failed"), key=lambda e: e.timestamp)
    if len(failures) < threshold:
        return None

    best: list[AuthEvent] = []
    left = 0
    for right, event in enumerate(failures):
        while event.timestamp - failures[left].timestamp > window:
            left += 1
        candidate = failures[left:right + 1]
        if len(candidate) > len(best):
            best = candidate
    if len(best) < threshold:
        return None
    return {
        "type": "repeated_failed_logins",
        "severity": "medium",
        "source_ip": best[0].source_ip,
        "window_start": best[0].timestamp.isoformat(sep=" "),
        "window_end": best[-1].timestamp.isoformat(sep=" "),
        "failed_attempts": len(best),
        "targeted_usernames": sorted({event.username for event in best}),
        "summary": (
            f"{len(best)} failed SSH password attempts from {best[0].source_ip} "
            f"within {window.total_seconds() // 60:.0f} minutes."
        ),
    }


def analyze(
    events: list[AuthEvent],
    skipped_lines: int = 0,
    threshold: int = 5,
    window_minutes: int = 10,
    correlation_failures: int = 3,
    lookback_minutes: int = 15,
) -> dict:
    if threshold < 2 or window_minutes < 1 or correlation_failures < 1 or lookback_minutes < 1:
        raise ValueError("Thresholds and time windows must be positive (failed-login threshold must be at least 2).")

    by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in events:
        by_ip[event.source_ip].append(event)

    alerts: list[dict] = []
    for source_ip, source_events in sorted(by_ip.items()):
        burst = _failed_burst(source_events, threshold, timedelta(minutes=window_minutes))
        if burst:
            alerts.append(burst)

        failures = [event for event in source_events if event.outcome == "failed"]
        successes = [event for event in source_events if event.outcome == "accepted"]
        lookback = timedelta(minutes=lookback_minutes)
        for success in successes:
            preceding = [
                event for event in failures
                if timedelta(0) <= success.timestamp - event.timestamp <= lookback
            ]
            if len(preceding) >= correlation_failures:
                alerts.append({
                    "type": "successful_login_after_repeated_failures",
                    "severity": "high",
                    "source_ip": source_ip,
                    "username": success.username,
                    "timestamp": success.timestamp.isoformat(sep=" "),
                    "preceding_failed_attempts": len(preceding),
                    "targeted_usernames": sorted({event.username for event in preceding}),
                    "summary": (
                        f"A successful SSH login for {success.username} from {source_ip} "
                        f"followed {len(preceding)} failed attempt(s) within {lookback_minutes} minutes."
                    ),
                })

    alerts.sort(key=lambda alert: (alert.get("timestamp") or alert.get("window_start", ""), alert["type"]))
    return {
        "tool": "linux-auth-log-triage",
        "events_parsed": len(events),
        "lines_skipped": skipped_lines,
        "alerts": alerts,
        "note": "Alerts identify patterns for human review; they do not prove malicious activity.",
    }


def _render(report: dict) -> str:
    lines = [
        "Linux SSH Authentication Log Triage",
        f"Parsed events: {report['events_parsed']}  |  Skipped lines: {report['lines_skipped']}",
        "",
    ]
    if not report["alerts"]:
        lines.append("No configured patterns were found in the parsed events.")
    else:
        for number, alert in enumerate(report["alerts"], start=1):
            lines.append(f"{number}. [{alert['severity'].upper()}] {alert['type']}")
            lines.append(f"   {alert['summary']}")
            if alert.get("targeted_usernames"):
                lines.append(f"   Usernames seen: {', '.join(alert['targeted_usernames'])}")
            if alert.get("timestamp"):
                lines.append(f"   Successful login: {alert['timestamp']}")
            else:
                lines.append(f"   Observed: {alert['window_start']} to {alert['window_end']}")
    lines.extend(["", f"Note: {report['note']}"])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logfile", nargs="?", type=Path, help="Linux auth.log or sshd journal export; reads stdin if omitted")
    parser.add_argument("--year", type=int, default=datetime.now().year, help="year for syslog timestamps without a year (default: current year)")
    parser.add_argument("--threshold", type=int, default=5, help="failed attempts from one IP in the configured window (default: 5)")
    parser.add_argument("--window", type=int, default=10, help="minutes for repeated-failure detection (default: 10)")
    parser.add_argument("--correlation-failures", type=int, default=3, help="prior failures required before flagging a success (default: 3)")
    parser.add_argument("--lookback", type=int, default=15, help="minutes before a success to correlate (default: 15)")
    parser.add_argument("--json", dest="json_path", type=Path, help="also write the full report as JSON to this path")
    args = parser.parse_args(argv)
    try:
        if args.logfile:
            with args.logfile.open(encoding="utf-8", errors="replace") as stream:
                events, skipped = parse_lines(stream, args.year)
        else:
            events, skipped = parse_lines(sys.stdin, args.year)
        report = analyze(events, skipped, args.threshold, args.window, args.correlation_failures, args.lookback)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(_render(report))
    if args.json_path:
        try:
            args.json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        except OSError as error:
            parser.error(f"could not write JSON report: {error}")
        print(f"\nJSON report saved to {args.json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
