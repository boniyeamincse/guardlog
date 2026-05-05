# guardlog

> Lightweight, fast, real-time CLI security log analyzer for developers and DevOps engineers.

[![npm version](https://img.shields.io/npm/v/guardlog)](https://www.npmjs.com/package/guardlog)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Node.js CI](https://github.com/boniyeamincse/guardlog/actions/workflows/ci.yml/badge.svg)](https://github.com/boniyeamincse/guardlog/actions)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18-brightgreen)](https://nodejs.org)

**guardlog** scans Nginx, Apache, and API access logs for security threats — brute force attacks, SQL injection, XSS, malicious bots, and directory scans — and gives you a color-coded risk report in seconds. Use it in your terminal, CI/CD pipeline, or as a Node.js library.

---

## Table of Contents

- [Why guardlog?](#why-guardlog)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Use Cases](#use-cases)
- [CLI Reference](#cli-reference)
- [Usage Examples](#usage-examples)
- [Log Filtering](#log-filtering)
- [Webhook Alerts](#webhook-alerts)
- [Output Formats](#output-formats)
- [Exit Codes](#exit-codes)
- [Supported Log Formats](#supported-log-formats)
- [Detection Rules](#detection-rules)
- [CI/CD Integration](#cicd-integration)
- [Node.js API](#nodejs-api)
- [Plugin API](#plugin-api)
- [Architecture](#architecture)
- [Running Tests](#running-tests)
- [Contributing](#contributing)
- [License](#license)

---

## Why guardlog?

| Problem | guardlog solution |
|---|---|
| You got breached — when did it start? | Scan historical logs in seconds |
| Server is slow — is someone brute-forcing? | Live monitor mode shows threats in real time |
| CI pipeline has no security gate | `--ci` exits `1` on HIGH risk — blocks the deploy |
| Log files are 2 GB | Streaming parser — never loads the full file into memory |
| Need to alert the team on Slack | `--webhook` sends a formatted Slack message automatically |

---

## Features

### 🚨 Threat Detection Engine

| Detector | What it catches |
|---|---|
| **Brute Force** | Repeated 401/403/429s on login endpoints; high-frequency IP bursts |
| **SQL Injection** | 18+ signatures: `UNION SELECT`, `DROP TABLE`, `SLEEP()`, `xp_cmdshell`, encoded variants |
| **XSS** | `<script>`, `onerror=`, `alert()`, `document.cookie`, encoded payloads |
| **Bot / Scanner** | 20+ UA blacklist entries (sqlmap, nikto, nuclei, nmap…); missing UA; frequency bursts |
| **404 Scan / Probe** | Directory brute force floods; `.env`, `.git/`, `wp-config.php` probes |

### 📊 Risk Scoring

- `LOW` / `MEDIUM` / `HIGH` classification
- Automatic threat aggregation and severity-based summary

### 🧾 Output Formats

- **Terminal** — color-coded, human-readable (powered by chalk)
- **JSON** — structured, machine-readable (`--json` or `--output report.json`)
- **CSV** — spreadsheet-friendly (`--csv` or `--output report.csv`)

### ⚡ Performance

- Streaming architecture — `fs.createReadStream` + `readline`, O(n), no full-file memory load
- Supports plain text and gzipped (`.gz`) rotated logs

### 🔌 Extensible

- Plugin API — add custom scanner modules at runtime
- Webhook alerts — POST reports to any HTTP endpoint or Slack

---

## Prerequisites

- **Node.js** v18 or later ([download](https://nodejs.org))
- **npm** v9 or later (included with Node.js)

Check your versions:

```bash
node --version   # should be >= v18.0.0
npm --version    # should be >= 9.0.0
```

---

## Installation

```bash
# Global install — use guardlog anywhere in your terminal
npm install -g guardlog

# Verify install
guardlog --version
guardlog --help
```

No global install? Use `npx` — runs without installing:

```bash
npx guardlog scan ./access.log
```

---

## Quick Start

**Your first scan in under 60 seconds:**

```bash
# 1. Install
npm install -g guardlog

# 2. Scan your Nginx or Apache access log
guardlog scan /var/log/nginx/access.log

# 3. See a color-coded security report in your terminal
```

**Don't have a log file handy? Create a test one:**

```bash
cat > /tmp/test.log << 'EOF'
192.168.1.10 - - [05/May/2026:10:00:01 +0000] "GET /login HTTP/1.1" 401 512 "-" "Mozilla/5.0"
192.168.1.10 - - [05/May/2026:10:00:02 +0000] "GET /login HTTP/1.1" 401 512 "-" "Mozilla/5.0"
192.168.1.10 - - [05/May/2026:10:00:03 +0000] "GET /login HTTP/1.1" 401 512 "-" "Mozilla/5.0"
10.0.0.5 - - [05/May/2026:10:00:04 +0000] "GET /index.php?id=1+UNION+SELECT+1,2,3-- HTTP/1.1" 200 800 "-" "sqlmap/1.7"
10.0.0.5 - - [05/May/2026:10:00:05 +0000] "GET /.env HTTP/1.1" 404 0 "-" "curl/7.88"
EOF

guardlog scan /tmp/test.log
```

---

## Use Cases

### 1. Incident Response — "Were we attacked?"

After an incident, scan historical logs to identify when the attack started, which IPs were involved, and what techniques were used.

```bash
guardlog scan /var/log/nginx/access.log --output incident-report.json
```

---

### 2. Daily Security Audit

Run guardlog on a schedule (cron) to receive a daily security summary.

```bash
# Run every day at 6 AM — save report with date in filename
0 6 * * * guardlog scan /var/log/nginx/access.log --output /var/reports/daily-$(date +\%F).json
```

---

### 3. CI/CD Security Gate

Block a deployment when HIGH-risk patterns appear in staging logs.

```bash
guardlog scan staging-access.log --ci
# exits 0 = safe, 1 = HIGH risk (blocks the pipeline)
```

---

### 4. Real-time Monitoring

Watch a live web server log for threats as they arrive — like `tail -f` with threat intelligence.

```bash
guardlog monitor --live /var/log/nginx/access.log
```

---

### 5. Slack / Team Alerts

Send a formatted security report to your team's Slack channel after each scan.

```bash
guardlog scan /var/log/nginx/access.log \
  --webhook https://hooks.slack.com/services/T.../B.../xxx
```

---

### 6. Investigate a Suspicious IP

Analyze only the traffic from one IP or subnet.

```bash
guardlog scan access.log --filter-ip 203.0.113.42
guardlog scan access.log --filter-ip 10.0.0.0/8
```

---

### 7. Scan Rotated (Compressed) Logs

Old logs are usually gzipped. guardlog decompresses them automatically.

```bash
guardlog scan /var/log/nginx/access.log.1.gz
```

---

## CLI Reference

### `scan` command

```
guardlog scan <file> [options]
```

Analyze a log file for security threats. Supports plain text and `.gz` files.

| Flag | Description | Example |
|------|-------------|---------|
| `--json` | Print JSON report to stdout | `--json` |
| `--csv` | Print CSV report to stdout | `--csv` |
| `--output <path>` | Save report to file (format auto-detected: `.json` or `.csv`) | `--output report.json` |
| `--ci` | Exit code `1` if HIGH risk, `0` if safe | `--ci` |
| `--filter-ip <ip>` | Only include entries from this IP or CIDR range | `--filter-ip 10.0.0.0/8` |
| `--filter-status <code>` | Only include entries with this HTTP status code | `--filter-status 401` |
| `--since <datetime>` | Only include entries at or after this time (ISO 8601) | `--since 2026-05-01T00:00:00Z` |
| `--until <datetime>` | Only include entries at or before this time (ISO 8601) | `--until 2026-05-02T00:00:00Z` |
| `--path-filter <regex>` | Only include entries whose URL path matches this regex | `--path-filter ^/api/` |
| `--webhook <url>` | POST the JSON report to this URL after scanning | `--webhook https://hooks.slack.com/...` |

---

### `monitor` command

```
guardlog monitor --live <file>
```

Watch a log file in real-time and display threat reports as new lines arrive. Press `Ctrl+C` to stop.

| Flag | Description | Required |
|------|-------------|----------|
| `--live <file>` | Path to the log file to watch | Yes |

---

## Usage Examples

### Basic scan (terminal output)

```bash
guardlog scan /var/log/nginx/access.log
```

### JSON output to stdout

```bash
guardlog scan access.log --json
```

### CSV output to stdout

```bash
guardlog scan access.log --csv
```

### Save report to file

```bash
guardlog scan access.log --output report.json
guardlog scan access.log --output report.csv
```

### CI mode

```bash
guardlog scan access.log --ci
echo "Exit: $?"   # 0 = safe, 1 = HIGH risk, 2 = error
```

### Scan a gzipped rotated log

```bash
guardlog scan /var/log/nginx/access.log.1.gz
```

### Live monitor mode

```bash
guardlog monitor --live /var/log/nginx/access.log
```

### CI + Slack alert combined

```bash
guardlog scan access.log --ci \
  --webhook https://hooks.slack.com/services/T.../B.../xxx
```

---

## Log Filtering

All filters can be combined. An entry must pass **every** active filter to be included.

```bash
# Specific IP only
guardlog scan access.log --filter-ip 192.168.1.55

# Entire subnet (CIDR)
guardlog scan access.log --filter-ip 10.0.0.0/8

# Only 401 Unauthorized responses
guardlog scan access.log --filter-status 401

# Time window
guardlog scan access.log \
  --since "2026-05-01T00:00:00Z" \
  --until "2026-05-02T00:00:00Z"

# Only /api/ requests
guardlog scan access.log --path-filter "^/api/"

# Combine: 404s from a subnet in a date range
guardlog scan access.log \
  --filter-ip 10.0.0.0/8 \
  --filter-status 404 \
  --since "2026-05-01"
```

---

## Webhook Alerts

guardlog POSTs a JSON security report to any HTTP/HTTPS endpoint after scanning. Slack Incoming Webhooks are auto-detected and sent with color-coded formatting (green/yellow/red by risk level).

```bash
# Generic HTTP endpoint
guardlog scan access.log --webhook https://alerts.myapp.com/hooks/security

# Slack Incoming Webhook
guardlog scan access.log --webhook https://hooks.slack.com/services/T.../B.../xxx

# Alert AND gate the pipeline
guardlog scan access.log --ci \
  --webhook https://hooks.slack.com/services/T.../B.../xxx
```

---

## Output Formats

### Terminal (default)

Color-coded human-readable report. Green = LOW, yellow = MEDIUM, red = HIGH.

### JSON

```bash
guardlog scan access.log --json
guardlog scan access.log --output report.json
```

```json
{
  "file": "access.log",
  "summary": {
    "total_requests": 12000,
    "suspicious_requests": 230,
    "risk_level": "HIGH"
  },
  "threats": {
    "brute_force": 12,
    "sql_injection": 5,
    "xss": 3,
    "bot_activity": 40,
    "scan_detection": 18
  },
  "top_attacker_ips": [
    { "ip": "192.168.1.10", "count": 300, "reason": "brute_force" }
  ],
  "timestamp": "2026-05-05T00:00:00.000Z"
}
```

### CSV

```bash
guardlog scan access.log --csv
guardlog scan access.log --output report.csv
```

```csv
# guardlog Security Report
# Generated: 2026-05-05T00:00:00.000Z

section,file,total_requests,suspicious_requests,risk_level,brute_force,sql_injection,xss,bot_activity,scan_detection
summary,access.log,12000,230,HIGH,12,5,3,40,18

rank,ip,hit_count,reason
1,192.168.1.10,300,brute_force
2,10.0.0.50,120,"sql_injection, bot_activity"
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Safe — no HIGH risk detected (or `--ci` not used) |
| `1` | HIGH risk detected (`--ci` flag only) |
| `2` | Error — file not found, parse failure, etc. |

---

## Supported Log Formats

| Format | Example line |
|--------|-------------|
| **Apache / Nginx Combined** | `127.0.0.1 - - [05/May/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 612 "-" "Mozilla/5.0"` |
| **W3C / IIS Extended** | `#Fields: date time c-ip cs-method cs-uri-stem sc-status` |
| **Rotated logs** (`.gz`) | Decompressed automatically via `zlib` |

---

## Detection Rules

### Brute Force
- Same IP with ≥ 10 failed auth responses (`401` / `403` / `429`) to login endpoints within 60 seconds
- Any IP exceeding 100 requests/minute to any endpoint
- Monitored endpoints: `/login`, `/signin`, `/auth`, `/wp-login.php`, `/admin`, `/api/login`

### SQL Injection (18+ patterns)
- `' OR 1=1`, `' AND 1=1`
- `UNION SELECT`, `DROP TABLE`, `DELETE FROM`, `UPDATE SET`, `INSERT INTO`
- `SLEEP()`, `BENCHMARK()`, `WAITFOR`
- `INFORMATION_SCHEMA`, `xp_cmdshell`, `sp_executesql`
- `CAST()`, `CONVERT()`
- URL-encoded variants (`%27`, `%3D`, `%3C`, etc.)
- Scanned in: URL path, query string, and User-Agent header

### XSS (17+ patterns)
- `<script>` tags (raw and URL-encoded)
- Event handlers: `onerror=`, `onclick=`, `onload=`, `onmouseover=`, …
- `alert()`, `confirm()`, `prompt()`, `eval()`
- `document.cookie`, `document.write()`, `window.location`
- `javascript:`, `vbscript:`, `data:text/html`
- HTML entity encoding variants (`&#x…;`)

### Bot / Scanner Detection

**User-Agent blacklist (20+ tools):**
`curl`, `wget`, `python-requests`, `python-urllib`, `libwww-perl`, `sqlmap`, `nikto`, `nmap`, `masscan`, `dirbuster`, `gobuster`, `wfuzz`, `nuclei`, `hydra`, `medusa`, `BurpSuite`, `OWASP ZAP`, `Acunetix`, `Nessus`, `Shodan`, `Censys`, `zgrab`

Also flags: missing/empty User-Agent, high-frequency IP bursts (> 200 req/min)

### 404 Scan / Directory Brute Force
- IPs generating ≥ 20 `404` responses within 60 seconds
- Sensitive path probes flagged immediately:
  `.env`, `wp-config.php`, `phpinfo.php`, `.git/`, `.bak`, `.sql`, `.zip`, `/cgi-bin/`, `/actuator/`, `/server-status`, `/manager/`

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Log Scan

on: [push]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install guardlog
        run: npm install -g guardlog

      - name: Scan access log
        run: guardlog scan access.log --ci --output guardlog-report.json

      - name: Upload security report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: guardlog-report
          path: guardlog-report.json
```

A full multi-node (18/20/22) workflow is at [.github/workflows/ci.yml](.github/workflows/ci.yml).

### GitLab CI

```yaml
security-scan:
  image: node:20
  script:
    - npm install -g guardlog
    - guardlog scan access.log --ci --output guardlog-report.json
  artifacts:
    paths:
      - guardlog-report.json
    when: always
```

---

## Node.js API

Use guardlog programmatically in your own Node.js scripts or applications.

```bash
npm install guardlog
```

```js
const { analyzeFile } = require('guardlog');

const result = await analyzeFile('./access.log', {
  filters: {
    ip: '10.0.0.0/8',           // CIDR filter
    status: 404,                 // HTTP status code filter
    since: '2026-05-01T00:00Z', // start time (ISO 8601)
    until: '2026-05-02T00:00Z', // end time (ISO 8601)
    pathPattern: '^/api/',       // URL path regex
  },
});

console.log(result.summary.risk_level);    // "HIGH" | "MEDIUM" | "LOW"
console.log(result.threats.sql_injection); // count of SQL injection hits
console.log(result.top_attacker_ips);      // [{ ip, count, reason }]
```

---

## Plugin API

Add custom threat detectors without modifying the core codebase.

```js
const { analyzeFile } = require('guardlog');

const pathTraversalPlugin = {
  name: 'pathTraversal',
  scan(entries) {
    const hits = entries.filter(e => e.path.includes('../'));
    const attackerIps = new Map();
    for (const h of hits) {
      attackerIps.set(h.ip, (attackerIps.get(h.ip) || 0) + 1);
    }
    return { hits, attackerIps };
  },
};

const result = await analyzeFile('./access.log', {
  plugins: [pathTraversalPlugin],
});

console.log(result.threats.plugins.pathTraversal); // count of flagged entries
```

**Plugin interface:**

```ts
interface Plugin {
  name: string;
  scan(entries: ParsedEntry[]): {
    hits: ParsedEntry[];
    attackerIps: Map<string, number>;
  };
}
```

Plugin errors are isolated — a failing plugin never crashes the main analyzer.

---

## Architecture

```
guardlog/
├── bin/
│   └── cli.js              # Commander CLI — all commands and flags
├── lib/
│   ├── analyzer.js         # Orchestrates scanners, filters, plugins → report
│   ├── parser.js           # Streaming Combined + W3C parser (.gz aware)
│   ├── monitor.js          # Live fs.watch tail mode
│   ├── reporter.js         # Terminal (chalk), JSON, CSV output formatters
│   └── scanner/
│       ├── bruteForce.js   # Sliding-window login/burst detection
│       ├── sqlInjection.js # SQL injection regex scanner (18+ patterns)
│       ├── xss.js          # XSS pattern scanner (17+ patterns)
│       ├── botDetector.js  # UA blacklist + path probing + frequency
│       └── scanDetector.js # 404 flood + sensitive path probe detection
├── utils/
│   ├── riskEngine.js       # LOW / MEDIUM / HIGH scoring
│   ├── filter.js           # Entry filtering (IP/CIDR, status, date, path)
│   └── webhook.js          # HTTP/HTTPS webhook alert sender (Slack-ready)
└── tests/
    └── guardlog.test.js    # 38 tests, Node.js built-in runner, zero test deps
```

---

## Running Tests

```bash
npm test
```

38 tests across 12 suites. Uses Node.js built-in `node:test` — **zero external test dependencies**.

---

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a pull request.

Quick steps:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Add tests for any new detection patterns
4. Commit: `git commit -m "feat: add my feature"`
5. Push and open a Pull Request

All PRs are automatically tested on Node.js 18, 20, and 22 via GitHub Actions.

---

## License

[MIT](LICENSE) — Copyright (c) 2026 guardlog contributors
