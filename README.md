# Linux Authentication Log Triage

A small Python command-line tool that reads Linux OpenSSH authentication logs and surfaces login patterns worth human review. It is designed as a learning project for log parsing, security triage, and defensive monitoring.

## What it does

- Parses OpenSSH `Failed password` and `Accepted` records from traditional syslog `auth.log` lines or ISO-timestamped journal exports.
- Flags bursts of failed password attempts from one source IP within a configurable time window.
- Flags a successful login when it follows several failed attempts from the same source IP within a configurable lookback period.
- Prints a concise console report and can optionally save the full report as JSON.
- Counts lines it does not understand so the operator can see that the input was only partly parsed.

Alerts are leads for investigation, not proof of an attack or account compromise. Shared networks, mistyped passwords, automated systems, and log gaps can all produce misleading patterns. The tool does not block connections, change accounts, or contact a remote service.

## Requirements

- Python 3.10 or later
- No third-party packages

## Run the sample

From this directory:

```sh
python auth_log_triage.py sample_auth.log --year 2026
```

The sample uses documentation-only IP addresses and synthetic log records. It demonstrates a failed-login burst and a later successful login from the same address.

Save a JSON report:

```sh
python auth_log_triage.py sample_auth.log --year 2026 --json report.json
```

Read from standard input:

```sh
cat /var/log/auth.log | python auth_log_triage.py --year 2026
```

On systems where the file is protected, run the command with an account that can read it or use `sudo` for the reading process only:

```sh
sudo cat /var/log/auth.log | python auth_log_triage.py --year 2026
```

Traditional syslog records do not include a year. Set `--year` to the year represented by the log file. ISO-timestamped records include their own year. The first version expects OpenSSH password success/failure records; other authentication messages are skipped and counted.

## Detection defaults

- **Repeated failures:** at least 5 failed password records from one source IP in a 10-minute sliding window.
- **Success after failures:** an accepted login from one source IP with at least 3 preceding failed password records from that IP in the previous 15 minutes.

These are adjustable, deliberately simple thresholds. They are not universal security policy. This initial version reports the densest failure window per source IP and creates a correlation alert for each accepted login that meets the lookback rule.

## Example output

```text
Linux SSH Authentication Log Triage
Parsed events: 7  |  Skipped lines: 1

1. [MEDIUM] repeated_failed_logins
   5 failed SSH password attempts from 203.0.113.44 within 10 minutes.
   Usernames seen: admin, student, test
   Observed: 2026-10-01 09:14:02 to 2026-10-01 09:18:06
2. [HIGH] successful_login_after_repeated_failures
   A successful SSH login for labuser from 203.0.113.44 followed 5 failed attempt(s) within 15 minutes.
   Usernames seen: admin, student, test
   Successful login: 2026-10-01 09:19:20

Note: Alerts identify patterns for human review; they do not prove malicious activity.
```

## Test

```sh
python -m unittest discover -s tests -v
```

The tests cover syslog and ISO timestamp parsing, IPv6, ignored lines, skipped-line counts, thresholds, and event ordering.

## Safe lab workflow

Use the included synthetic sample or logs from a Linux virtual machine that you own or are authorized to administer. Authentication logs can contain usernames, IP addresses, and other sensitive operational details. Review locally and remove or redact identifying data before sharing examples publicly.

## Next extensions

- Add a `--since` filter for large files.
- Add tests and parsing for additional SSH/PAM message formats.
- Produce a timeline grouped by account as well as source IP.
- Add a documented Sigma rule for a compatible log pipeline.
