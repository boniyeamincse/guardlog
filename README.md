# guardlog

> Lightweight, fast, real-time CLI security log analyzer for developers and DevOps engineers.

[![npm version](https://img.shields.io/npm/v/guardlog)](https://www.npmjs.com/package/guardlog)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Node.js CI](https://github.com/yourusername/guardlog/actions/workflows/ci.yml/badge.svg)](https://github.com/yourusername/guardlog/actions)

---

## Features

### ⚡ Core Log Scanning
- Nginx / Apache / API log file scanning
- Large file streaming — `fs.createReadStream` + `readline`, no full-file memory load
- O(n) processing engine
- Multi-format support: Apache/Nginx **Combined Log Format** and **W3C/IIS Extended** format
- **Rotated log support** — automatically decompresses `.gz` / `.gzip` files via `zlib`

### 🚨 Threat Detection Engine
| Detector | What it catches |
|---|---|
| **Brute Force** | Repeated 401/403/429s on login endpoints; high-frequency IP bursts |
| **SQL Injection** | 18+ signatures: `UNION SELECT`, `DROP TABLE`, `SLEEP()`, `xp_cmdshell`, encoded variants |
| **XSS** | `<script>`, `onerror=`, `alert()`, `document.cookie`, encoded payloads |
| **Bot / Scanner** | 20+ UA blacklist entries (curl, sqlmap, nikto, nuclei…); missing UA; frequency |
| **404 Scan / Probe** | Directory brute force floods; `.env`, `.bak`, `wp-config.php`, `.git/` probes |

### 📊 Risk Scoring System
- `LOW` / `MEDIUM` / `HIGH` classification
- Automatic threat aggregation and severity-based summary
- Percentage-of-traffic based escalation

### 🧾 Output System
- **Terminal** — color-coded, human-readable report (chalk)
- **JSON** — structured, machine-readable (`--json`, `--output report.json`)
- **CSV** — spreadsheet-friendly (`--csv`, `--output report.csv`)

### ⚙️ CLI Features
- `guardlog scan file.log`
- `guardlog scan file.log --json`
- `guardlog scan file.log --csv`
- `guardlog scan file.log --output report.json`
- `guardlog scan file.log --output report.csv`
- `guardlog scan file.log --ci`
- `guardlog monitor --live /var/log/nginx/access.log`

### 🔍 Log Filtering System
- Filter by IP address or CIDR range
- Filter by HTTP status code
- Filter by date/time range (`--since` / `--until`)
- Filter by URL path regex (`--path-filter`)

### 🔁 Real-time / Live Mode
- `tail -f` style file watching (`fs.watch`)
- Batch analysis on each flush interval
- Instant threat detection for new log lines

### 🚀 CI/CD Integration
- Exit code `0` = safe, `1` = HIGH risk, `2` = error
- GitHub Actions workflow included
- Pipeline security gate support

### 🔔 Webhook Alerts
- POST JSON report to any HTTP/HTTPS endpoint
- Built-in Slack Incoming Webhook format support
- Zero external dependencies (Node.js `https` module only)

### 🔌 Plugin Architecture
- Plug in custom scanner modules at runtime
- Each plugin receives the parsed entry stream
- Plugin errors are isolated — never crash the main analyzer

---

## Installation

```bash
# Global install (recommended for CLI usage)
npm install -g guardlog

# Or use with npx (no install)
npx guardlog scan ./access.log
```

---

## Usage

### Basic scan

```bash
guardlog scan ./access.log
```

### JSON output to stdout

```bash
guardlog scan ./access.log --json
```

### CSV output to stdout

```bash
guardlog scan ./access.log --csv
```

### Save report to file (auto-detects format by extension)

```bash
guardlog scan ./access.log --output report.json
guardlog scan ./access.log --output report.csv
```

### CI mode — exit code 1 when risk is HIGH

```bash
guardlog scan ./access.log --ci
```

### Scan a rotated (gzipped) log file

```bash
guardlog scan ./access.log.gz
```

### Live monitor mode

```bash
guardlog monitor --live /var/log/nginx/access.log
```

---

## Log Filtering

All filters can be combined. They are ANDed — an entry must pass every active filter.

```bash
# Only analyze traffic from a specific IP
guardlog scan access.log --filter-ip 192.168.1.55

# Only analyze a subnet (CIDR)
guardlog scan access.log --filter-ip 10.0.0.0/8

# Only analyze 401 (unauthorized) responses
guardlog scan access.log --filter-status 401

# Only analyze a time range
guardlog scan access.log --since "2026-05-01T00:00:00Z" --until "2026-05-02T00:00:00Z"

# Only analyze /api/ paths
guardlog scan access.log --path-filter "^/api/"

# Combine: 404s from a subnet since a date
guardlog scan access.log --filter-ip 10.0.0.0/8 --filter-status 404 --since "2026-05-01"
```

---

## Webhook Alerts

```bash
# Generic endpoint
guardlog scan access.log --webhook https://alerts.myapp.com/hooks/security

# Slack Incoming Webhook (auto-detected by hostname)
guardlog scan access.log --webhook https://hooks.slack.com/services/T.../B.../xxx

# Combine with CI mode
guardlog scan access.log --ci --webhook https://hooks.slack.com/services/...
```

The Slack payload includes risk level, threat breakdown, and top attacker IPs with color coding (green/yellow/red).

---

## JSON Report Format

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

---

## CSV Report Format

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
| `0`  | Safe — no HIGH risk detected (or `--ci` not used) |
| `1`  | HIGH risk detected (`--ci` flag only) |
| `2`  | Error (file not found, parse failure, etc.) |

---

## Supported Log Formats

- **Apache / Nginx Combined Log Format** (default)
- **W3C / IIS Extended Log Format**
- **Rotated logs** — `.gz` / `.gzip` files decompressed automatically

---

## Detection Rules

### Brute Force
- Same IP with ≥ 10 failed auth responses (`401` / `403` / `429`) to login endpoints within 60 seconds
- Any IP exceeding 100 requests/minute to any endpoint
- Detected endpoints: `/login`, `/signin`, `/auth`, `/wp-login.php`, `/admin`, `/api/login`

### SQL Injection (18+ patterns)
- `' OR 1=1`, `' AND 1=1`
- `UNION SELECT`, `DROP TABLE`, `DELETE FROM`, `UPDATE SET`, `INSERT INTO`
- `SLEEP()`, `BENCHMARK()`, `WAITFOR`
- `INFORMATION_SCHEMA`, `xp_cmdshell`, `sp_executesql`
- `CAST()`, `CONVERT()`
- URL-encoded variants (`%27`, `%3D`, `%3C`, etc.)
- Applied to URL path + query string + User-Agent header

### XSS (17+ patterns)
- `<script>` tags (raw and URL-encoded)
- Event handlers: `onerror=`, `onclick=`, `onload=`, `onmouseover=`, …
- `alert()`, `confirm()`, `prompt()`, `eval()`
- `document.cookie`, `document.write()`, `window.location`
- `javascript:`, `vbscript:`, `data:text/html`
- HTML entity encoding used in evasion (`&#x…;`)

### Bot / Scanner Detection
**User-Agent blacklist** (20+ entries):
`curl`, `wget`, `python-requests`, `python-urllib`, `libwww-perl`, `sqlmap`, `nikto`, `nmap`, `masscan`, `dirbuster`, `gobuster`, `wfuzz`, `nuclei`, `hydra`, `medusa`, `BurpSuite`, `OWASP ZAP`, `Acunetix`, `Nessus`, `Shodan`, `Censys`, `zgrab`

Also detects: missing/empty User-Agent, high-frequency IP bursts (> 200 req/min)

### 404 Scan / Directory Brute Force Detection
- IPs generating ≥ 20 `404` responses within 60 seconds
- Immediate flag for sensitive path probes:
  `.env`, `wp-config.php`, `phpinfo.php`, `.git/`, `.bak`, `.sql`, `.zip`, `/cgi-bin/`, `/actuator/`, `/server-status`, `/manager/`

---

## Plugin API

Write custom scanner plugins and pass them via the Node.js API:

```js
const { analyzeFile } = require('guardlog');

const myPlugin = {
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
  plugins: [myPlugin],
});

console.log(result.threats.plugins.pathTraversal); // count of flagged entries
```

Plugin interface:
```ts
interface Plugin {
  name: string;
  scan(entries: ParsedEntry[]): {
    hits: ParsedEntry[];
    attackerIps: Map<string, number>;
  };
}
```

---

## GitHub Actions Integration

```yaml
- name: Install guardlog
  run: npm install -g guardlog

- name: Scan access.log
  run: guardlog scan access.log --ci --output guardlog-report.json

- name: Upload security report
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: guardlog-report
    path: guardlog-report.json
```

A full multi-node workflow is at [.github/workflows/ci.yml](.github/workflows/ci.yml).

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

## Node.js API

```js
const { analyzeFile, analyzeEntries } = require('guardlog');

// Scan a file
const result = await analyzeFile('./access.log', {
  filters: {
    ip: '10.0.0.0/8',          // CIDR filter
    status: 404,                // status code filter
    since: '2026-05-01T00:00Z', // start time
    until: '2026-05-02T00:00Z', // end time
    pathPattern: '^/api/',      // path regex
  },
  plugins: [myPlugin],          // custom scanner plugins
});

console.log(result.summary.risk_level); // "HIGH" | "MEDIUM" | "LOW"
```

---

## Running Tests

```bash
npm test
```

38 tests across 12 suites. Uses Node.js built-in `node:test` — **zero external test dependencies**.

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Add tests for any new detection patterns
4. Commit: `git commit -m "feat: add my feature"`
5. Push and open a Pull Request

All PRs run through the CI pipeline automatically on Node.js 18, 20, and 22.

---

## License

[MIT](LICENSE) — Copyright (c) 2026 guardlog contributors

> Lightweight, fast, real-time CLI security log analyzer for developers and DevOps engineers.

[![npm version](https://img.shields.io/npm/v/guardlog)](https://www.npmjs.com/package/guardlog)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Node.js CI](https://github.com/boniyeamincse/guardlog/actions/workflows/ci.yml/badge.svg)](https://github.com/boniyeamincse/guardlog/actions)

---

## Features

- **Brute force detection** — identifies repeated failed login attempts and high-frequency IP bursts
- **SQL injection detection** — pattern-matched against 18+ known payload signatures
- **XSS detection** — covers script tags, event handlers, encoded payloads, and more
- **Bot & scanner detection** — flags curl, sqlmap, nikto, nuclei, dirbuster, and many others
- **Risk scoring** — `LOW` / `MEDIUM` / `HIGH` engine with CI-friendly exit codes
- **Streaming architecture** — uses `fs.createReadStream` + `readline`; O(n), no full-file load
- **Live monitor mode** — watches a file for new entries in real-time
- **JSON output** — structured reports for downstream tooling
- **GitHub Actions integration** — drop-in step for your CI/CD pipeline

---

## Installation

```bash
# Global install (recommended for CLI usage)
npm install -g guardlog

# Or use with npx
npx guardlog scan ./access.log
```

---

## Usage

### Scan a log file

```bash
guardlog scan ./access.log
```

### Output a JSON report to stdout

```bash
guardlog scan ./access.log --json
```

### Save a JSON report to a file

```bash
guardlog scan ./access.log --output report.json
```

### CI mode — exits with code 1 when risk is HIGH

```bash
guardlog scan ./access.log --ci
```

### Live monitor mode — watch a file for new threats in real-time

```bash
guardlog monitor --live /var/log/nginx/access.log
```

---

## JSON Report Format

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
    "bot_activity": 40
  },
  "top_attacker_ips": [
    {
      "ip": "192.168.1.10",
      "count": 300,
      "reason": "brute_force"
    }
  ],
  "timestamp": "2026-05-05T00:00:00.000Z"
}
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0`  | Safe — no HIGH risk detected (or `--ci` not used) |
| `1`  | HIGH risk detected (only with `--ci` flag) |
| `2`  | Error (file not found, parse failure, etc.) |

---

## Supported Log Formats

- **Apache / Nginx Combined Log Format** (default)
- **W3C / IIS Extended Log Format**

---

## Detection Rules

### Brute Force
- Same IP with ≥ 10 failed auth requests (`401` / `403` / `429`) to login endpoints within 60 seconds
- Any IP exceeding 100 requests/minute to any endpoint

### SQL Injection
Pattern coverage includes:
- `' OR 1=1`, `' AND 1=1`
- `UNION SELECT`, `DROP TABLE`, `DELETE FROM`
- `SLEEP()`, `BENCHMARK()`, `WAITFOR`
- `INFORMATION_SCHEMA`, `xp_cmdshell`, `sp_executesql`
- URL-encoded variants (`%27`, `%3D`, etc.)

### XSS
- `<script>` tags (including encoded)
- Event handlers: `onerror=`, `onclick=`, `onload=`, …
- `alert()`, `confirm()`, `prompt()`, `eval()`
- `document.cookie`, `window.location`
- `javascript:`, `vbscript:`, `data:text/html`

### Bot / Scanner Detection
User-Agent blacklist includes: `curl`, `wget`, `python-requests`, `sqlmap`, `nikto`, `nuclei`, `nmap`, `masscan`, `dirbuster`, `gobuster`, `hydra`, `Burp Suite`, `OWASP ZAP`, `Acunetix`, `Nessus`, `Shodan`, and more.

Scanner path probes: `.env`, `wp-config.php`, `phpinfo.php`, `.git/`, `/admin/`, `/phpmyadmin`, `/backup`, and more.

---

## GitHub Actions Integration

```yaml
- name: Install guardlog
  run: npm install -g guardlog

- name: Scan access.log
  run: guardlog scan access.log --ci --output guardlog-report.json

- name: Upload security report
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: guardlog-report
    path: guardlog-report.json
```

A full workflow file is available at [.github/workflows/ci.yml](.github/workflows/ci.yml).

---

## Architecture

```
guardlog/
├── bin/
│   └── cli.js              # Commander-based CLI entry point
├── lib/
│   ├── analyzer.js         # Orchestrates all scanners, builds report
│   ├── parser.js           # Streaming log line parser (Combined + W3C)
│   ├── monitor.js          # Live file watcher (fs.watch)
│   ├── reporter.js         # Terminal (chalk) and JSON output formatters
│   └── scanner/
│       ├── bruteForce.js   # Sliding-window brute force detection
│       ├── sqlInjection.js # SQL injection regex scanner
│       ├── xss.js          # XSS pattern scanner
│       └── botDetector.js  # UA + path + frequency bot detection
├── utils/
│   └── riskEngine.js       # LOW / MEDIUM / HIGH scoring
└── tests/
    └── guardlog.test.js    # Node.js built-in test runner
```

---

## Running Tests

```bash
npm test
```

Tests use Node.js's built-in `node:test` runner — zero external test dependencies.

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m "feat: add my feature"`
4. Push and open a Pull Request

Please keep PRs focused. Add tests for any new scanner patterns. All PRs are run through the CI pipeline automatically.

---

## License

[MIT](LICENSE) — Copyright (c) 2026 guardlog contributors
