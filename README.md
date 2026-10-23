# OpenSSH Authentication Log Analyzer

An offline CLI that reads OpenSSH authentication log files, counts failed and successful login events by source IP, and flags IPs that exceed a configurable failure threshold. Supports plain text and gzip-compressed files; only Python's standard library is required.

## Run

~~~sh
python log_analyzer.py --input /var/log/auth.log
python log_analyzer.py --input auth.log.gz --threshold 10 --format json --output report.json
python log_analyzer.py --input auth.log --threshold 5 --fail-on-alert
~~~

The analyzer recognizes common sshd password, public-key, and keyboard-interactive messages. It streams the input and does not upload or retain raw log lines. Reports include failed usernames to support local incident review.

The threshold counts matching events across the whole supplied file, not a time window. This is batch triage, not a live SIEM, an intrusion detector, or proof that an IP is malicious. Other log formats and authentication methods may not match these patterns; review the source log when the report has unmatched lines.