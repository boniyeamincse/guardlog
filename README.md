# guardlog

> Lightweight, fast, real-time CLI security log analyzer for developers and DevOps engineers.

[![npm version](https://img.shields.io/npm/v/guardlog)](https://www.npmjs.com/package/guardlog)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Node.js CI](https://github.com/yourusername/guardlog/actions/workflows/ci.yml/badge.svg)](https://github.com/yourusername/guardlog/actions)

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
