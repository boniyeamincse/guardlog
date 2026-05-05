# Contributing to guardlog

Thank you for your interest in contributing! guardlog is an open source project and contributions of all kinds are welcome — bug fixes, new detection patterns, documentation improvements, and feature ideas.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Project Structure](#project-structure)
- [How to Contribute](#how-to-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Features](#suggesting-features)
  - [Submitting a Pull Request](#submitting-a-pull-request)
- [Development Setup](#development-setup)
- [Running Tests](#running-tests)
- [Writing Tests](#writing-tests)
- [Adding Detection Patterns](#adding-detection-patterns)
- [Commit Message Convention](#commit-message-convention)
- [Code Style](#code-style)

---

## Code of Conduct

Be respectful and constructive. This project follows the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/) Code of Conduct. Harassment, discrimination, or abusive behavior of any kind will not be tolerated.

---

## Getting Started

1. **Fork** the repository on GitHub
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/guardlog.git
   cd guardlog
   ```
3. **Install dependencies:**
   ```bash
   npm install
   ```
4. **Run the tests** to confirm everything works:
   ```bash
   npm test
   ```

---

## Project Structure

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

## How to Contribute

### Reporting Bugs

Before opening an issue, please:

1. Search [existing issues](https://github.com/boniyeamincse/guardlog/issues) to avoid duplicates
2. Confirm you are using the latest version: `npm install -g guardlog`

When opening a bug report, include:

- **guardlog version** (`guardlog --version`)
- **Node.js version** (`node --version`)
- **OS and OS version**
- **Command you ran** and the **full output or error message**
- **Log file format** (Apache/Nginx/W3C/other) if relevant
- A **minimal reproducible example** if possible

---

### Suggesting Features

Open a [GitHub Issue](https://github.com/boniyeamincse/guardlog/issues/new) with:

- A clear description of the problem it solves
- The expected behavior / proposed API or CLI flag
- Any relevant examples or prior art

---

### Submitting a Pull Request

1. Create a feature branch from `master`:
   ```bash
   git checkout -b feature/my-feature
   ```

2. Make your changes. Keep PRs **focused** — one feature or fix per PR.

3. Add or update tests for your changes (see [Writing Tests](#writing-tests)).

4. Run the full test suite and confirm all tests pass:
   ```bash
   npm test
   ```

5. Commit with a descriptive message following the [convention below](#commit-message-convention).

6. Push your branch and open a Pull Request against `master`:
   ```bash
   git push origin feature/my-feature
   ```

7. Fill in the PR template — describe what changed and why.

All PRs are automatically tested on Node.js 18, 20, and 22 via GitHub Actions. A PR will not be merged until CI passes.

---

## Development Setup

**Requirements:**
- Node.js 18 or later
- npm 9 or later

```bash
# Install dependencies
npm install

# Run CLI locally without installing globally
node bin/cli.js --help
node bin/cli.js scan /path/to/access.log

# Run tests
npm test
```

No build step is required. guardlog is plain CommonJS — edit and run directly.

---

## Running Tests

```bash
npm test
```

Tests use Node.js's built-in `node:test` runner. There are **zero external test dependencies**.

The test suite covers:
- Log parsing (Combined Format, W3C Format)
- All five threat detectors (brute force, SQL injection, XSS, bot detection, scan detection)
- Risk scoring engine
- Entry filtering (IP/CIDR, status, date range, path regex)
- JSON, CSV, and terminal reporters
- Webhook sender
- Plugin API

---

## Writing Tests

All tests live in `tests/guardlog.test.js`. Use Node.js built-in `node:test` and `node:assert` — **do not add test framework dependencies**.

**Example test structure:**

```js
const { test, describe } = require('node:test');
const assert = require('node:assert/strict');

describe('myScanner', () => {
  test('detects my new pattern', () => {
    const entries = [
      { ip: '1.2.3.4', method: 'GET', path: '/evil?param=payload', status: 200, ua: 'Mozilla/5.0' }
    ];
    const { hits } = require('../lib/scanner/myScanner').scan(entries);
    assert.equal(hits.length, 1);
  });

  test('does not flag safe entries', () => {
    const entries = [
      { ip: '1.2.3.4', method: 'GET', path: '/safe', status: 200, ua: 'Mozilla/5.0' }
    ];
    const { hits } = require('../lib/scanner/myScanner').scan(entries);
    assert.equal(hits.length, 0);
  });
});
```

**Rules:**
- Every new detection pattern must have at least one **positive test** (it fires) and one **negative test** (it does not false-positive).
- Keep tests fast and self-contained — no network calls, no real log files.

---

## Adding Detection Patterns

### SQL Injection / XSS patterns

Pattern arrays are in `lib/scanner/sqlInjection.js` and `lib/scanner/xss.js`. To add a new signature:

1. Add the regex or string to the relevant array
2. Add a test case in `tests/guardlog.test.js` with a payload that triggers it and one that does not
3. Update the detection rule count in `README.md` if the total changes

### New threat detector module

If you are adding an entirely new threat category (e.g. path traversal, SSRF):

1. Create `lib/scanner/myDetector.js` exporting a `scan(entries)` function:
   ```js
   'use strict';
   function scan(entries) {
     const hits = [];
     const attackerIps = new Map();
     for (const e of entries) {
       if (/* your detection logic */) {
         hits.push(e);
         attackerIps.set(e.ip, (attackerIps.get(e.ip) || 0) + 1);
       }
     }
     return { hits, attackerIps };
   }
   module.exports = { scan };
   ```
2. Register it in `lib/analyzer.js`
3. Add it to the `threats` object in the report output
4. Update `README.md` (Threat Detection Engine table, Detection Rules section)
5. Add tests

### Bot / Scanner User-Agent blacklist

The UA blacklist is in `lib/scanner/botDetector.js`. Add the tool name as a lowercase string. Include a test.

---

## Commit Message Convention

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>: <short summary>
```

| Type | When to use |
|------|-------------|
| `feat` | New feature or detection pattern |
| `fix` | Bug fix |
| `test` | Adding or updating tests only |
| `docs` | Documentation changes only |
| `refactor` | Code change that is not a fix or feature |
| `chore` | Dependency updates, build config, CI changes |

**Examples:**
```
feat: add path traversal detector
fix: handle missing User-Agent header in botDetector
test: add negative test cases for XSS scanner
docs: add webhook Slack example to README
chore: update commander to v12
```

---

## Code Style

- **No linter config is enforced**, but please match the existing style:
  - `'use strict';` at the top of every file
  - 2-space indentation
  - Single quotes for strings
  - `const` / `let` — never `var`
  - Async/await over raw Promise chains
  - No external runtime dependencies unless absolutely necessary

---

## Questions?

Open a [GitHub Issue](https://github.com/boniyeamincse/guardlog/issues) or start a [Discussion](https://github.com/boniyeamincse/guardlog/discussions). We are happy to help.
