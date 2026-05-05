'use strict';

/**
 * Tests for guardlog
 * Uses Node.js built-in test runner (node --test)
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('fs');
const os = require('os');

const { parseLine, parseFile } = require('../lib/parser');
const { scan: scanBF } = require('../lib/scanner/bruteForce');
const { scan: scanSQL } = require('../lib/scanner/sqlInjection');
const { scan: scanXSS } = require('../lib/scanner/xss');
const { scan: scanBot } = require('../lib/scanner/botDetector');
const { analyzeEntries } = require('../lib/analyzer');
const { calculateRisk } = require('../utils/riskEngine');
const { toJSON } = require('../lib/reporter');
const { toCSV } = require('../lib/reporter');
const { scan: scanSD } = require('../lib/scanner/scanDetector');
const { applyFilters } = require('../utils/filter');

// ── Parser tests ─────────────────────────────────────────────────────────────
describe('Parser', () => {
  test('parses a valid Combined Log Format line', () => {
    const line = '192.168.1.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326 "http://example.com" "Mozilla/5.0"';
    const entry = parseLine(line);
    assert.ok(entry, 'should return a parsed entry');
    assert.equal(entry.ip, '192.168.1.1');
    assert.equal(entry.method, 'GET');
    assert.equal(entry.path, '/index.html');
    assert.equal(entry.status, 200);
    assert.equal(entry.userAgent, 'Mozilla/5.0');
  });

  test('returns null for blank lines', () => {
    assert.equal(parseLine(''), null);
    assert.equal(parseLine('  '), null);
  });

  test('returns null for comment lines', () => {
    assert.equal(parseLine('#Fields: date time cs-ip'), null);
  });

  test('parses file and streams entries', async () => {
    const tmpFile = path.join(os.tmpdir(), 'guardlog-test.log');
    const line = '10.0.0.1 - - [01/Jan/2024:00:00:00 +0000] "POST /login HTTP/1.1" 401 512 "-" "curl/7.68"';
    fs.writeFileSync(tmpFile, `${line}\n${line}\n`, 'utf8');

    const entries = [];
    const stats = await parseFile(tmpFile, e => entries.push(e));

    assert.equal(stats.total, 2);
    assert.equal(stats.parsed, 2);
    assert.equal(entries.length, 2);
    assert.equal(entries[0].ip, '10.0.0.1');
    fs.unlinkSync(tmpFile);
  });
});

// ── Brute Force Scanner ───────────────────────────────────────────────────────
describe('BruteForce Scanner', () => {
  test('detects repeated 401s on /login within time window', () => {
    const now = Date.now();
    const entries = Array.from({ length: 15 }, (_, i) => ({
      ip: '1.2.3.4',
      timestamp: now + i * 1000,
      method: 'POST',
      path: '/login',
      status: 401,
      size: '100',
      referer: '-',
      userAgent: 'Mozilla/5.0',
      raw: '',
    }));

    const { hits, attackerIps } = scanBF(entries);
    assert.ok(hits.length > 0, 'should detect brute force hits');
    assert.ok(attackerIps.has('1.2.3.4'));
  });

  test('ignores legitimate successful logins', () => {
    const now = Date.now();
    const entries = Array.from({ length: 15 }, (_, i) => ({
      ip: '5.6.7.8',
      timestamp: now + i * 1000,
      method: 'POST',
      path: '/login',
      status: 200,  // success
      size: '100',
      referer: '-',
      userAgent: 'Mozilla/5.0',
      raw: '',
    }));

    const { hits } = scanBF(entries);
    assert.equal(hits.length, 0);
  });
});

// ── SQL Injection Scanner ─────────────────────────────────────────────────────
describe('SQL Injection Scanner', () => {
  const makeEntry = (path, ua = 'Mozilla/5.0') => ({
    ip: '9.8.7.6',
    timestamp: Date.now(),
    method: 'GET',
    path,
    status: 200,
    size: '-',
    referer: '-',
    userAgent: ua,
    raw: '',
  });

  test('detects UNION SELECT', () => {
    const { hits } = scanSQL([makeEntry("/search?q=1' UNION SELECT * FROM users--")]);
    assert.equal(hits.length, 1);
  });

  test('detects DROP TABLE', () => {
    const { hits } = scanSQL([makeEntry('/api?id=1; DROP TABLE users;')]);
    assert.equal(hits.length, 1);
  });

  test('passes clean requests', () => {
    const { hits } = scanSQL([makeEntry('/about'), makeEntry('/products?id=42')]);
    assert.equal(hits.length, 0);
  });
});

// ── XSS Scanner ───────────────────────────────────────────────────────────────
describe('XSS Scanner', () => {
  const makeEntry = (path) => ({
    ip: '1.1.1.1',
    timestamp: Date.now(),
    method: 'GET',
    path,
    status: 200,
    size: '-',
    referer: '-',
    userAgent: 'Mozilla/5.0',
    raw: '',
  });

  test('detects <script> tag', () => {
    const { hits } = scanXSS([makeEntry('/search?q=<script>alert(1)</script>')]);
    assert.ok(hits.length > 0);
  });

  test('detects onerror= attribute', () => {
    const { hits } = scanXSS([makeEntry('/img?src=x onerror=alert(1)')]);
    assert.ok(hits.length > 0);
  });

  test('passes clean requests', () => {
    const { hits } = scanXSS([makeEntry('/home'), makeEntry('/api/users')]);
    assert.equal(hits.length, 0);
  });
});

// ── Bot Detector ──────────────────────────────────────────────────────────────
describe('Bot Detector', () => {
  const makeEntry = (ua, path = '/') => ({
    ip: '2.2.2.2',
    timestamp: Date.now(),
    method: 'GET',
    path,
    status: 200,
    size: '-',
    referer: '-',
    userAgent: ua,
    raw: '',
  });

  test('detects curl user-agent', () => {
    const { hits } = scanBot([makeEntry('curl/7.68.0')]);
    assert.equal(hits.length, 1);
  });

  test('detects sqlmap user-agent', () => {
    const { hits } = scanBot([makeEntry('sqlmap/1.5')]);
    assert.equal(hits.length, 1);
  });

  test('detects .env path probe', () => {
    const { hits } = scanBot([makeEntry('Mozilla/5.0', '/.env')]);
    assert.ok(hits.length > 0);
  });

  test('passes normal browser UA', () => {
    const { hits } = scanBot([makeEntry('Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120')]);
    assert.equal(hits.length, 0);
  });
});

// ── Risk Engine ───────────────────────────────────────────────────────────────
describe('Risk Engine', () => {
  test('returns HIGH for SQL injection', () => {
    assert.equal(calculateRisk({ bruteForce: 0, sqlInjection: 1, xss: 0, botActivity: 0 }, 1000), 'HIGH');
  });

  test('returns HIGH for XSS', () => {
    assert.equal(calculateRisk({ bruteForce: 0, sqlInjection: 0, xss: 1, botActivity: 0 }, 1000), 'HIGH');
  });

  test('returns MEDIUM for brute force', () => {
    assert.equal(calculateRisk({ bruteForce: 3, sqlInjection: 0, xss: 0, botActivity: 0 }, 1000), 'MEDIUM');
  });

  test('returns LOW for clean traffic', () => {
    assert.equal(calculateRisk({ bruteForce: 0, sqlInjection: 0, xss: 0, botActivity: 0 }, 1000), 'LOW');
  });
});

// ── Analyzer integration ──────────────────────────────────────────────────────
describe('Analyzer', () => {
  test('produces a valid report structure', () => {
    const entries = [
      {
        ip: '3.3.3.3',
        timestamp: Date.now(),
        method: 'GET',
        path: "/search?q=' OR 1=1",
        status: 200,
        size: '-',
        referer: '-',
        userAgent: 'Mozilla/5.0',
        raw: '',
      },
    ];

    const result = analyzeEntries(entries, 'test');
    assert.ok(result.summary);
    assert.ok(result.threats);
    assert.ok(Array.isArray(result.top_attacker_ips));
    assert.ok(typeof result.timestamp === 'string');
    assert.equal(result.summary.risk_level, 'HIGH');
    assert.ok(result.threats.sql_injection > 0);
  });

  test('toJSON produces valid JSON', () => {
    const entries = [];
    const result = analyzeEntries(entries, 'empty.log');
    const json = toJSON(result);
    const parsed = JSON.parse(json);
    assert.equal(parsed.summary.risk_level, 'LOW');
  });
});

// ── 404 Scan Detector ─────────────────────────────────────────────────────────
describe('Scan Detector', () => {
  test('detects .env path probe immediately', () => {
    const { hits } = scanSD([{
      ip: '5.5.5.5', timestamp: Date.now(), method: 'GET',
      path: '/.env', status: 404, size: '-', referer: '-',
      userAgent: 'Mozilla/5.0', raw: '',
    }]);
    assert.ok(hits.length > 0);
  });

  test('detects .bak file probe', () => {
    const { hits } = scanSD([{
      ip: '5.5.5.5', timestamp: Date.now(), method: 'GET',
      path: '/config.bak', status: 404, size: '-', referer: '-',
      userAgent: 'Mozilla/5.0', raw: '',
    }]);
    assert.ok(hits.length > 0);
  });

  test('detects 404 flood (directory brute force)', () => {
    const now = Date.now();
    const entries = Array.from({ length: 25 }, (_, i) => ({
      ip: '6.6.6.6',
      timestamp: now + i * 1000,
      method: 'GET',
      path: `/dir${i}/index.php`,
      status: 404,
      size: '-',
      referer: '-',
      userAgent: 'dirbuster/1.0',
      raw: '',
    }));
    const { hits, attackerIps } = scanSD(entries);
    assert.ok(hits.length > 0, 'should detect 404 flood');
    assert.ok(attackerIps.has('6.6.6.6'));
  });

  test('passes normal 404s below threshold', () => {
    const now = Date.now();
    const entries = Array.from({ length: 5 }, (_, i) => ({
      ip: '7.7.7.7',
      timestamp: now + i * 1000,
      method: 'GET',
      path: `/missing${i}`,
      status: 404,
      size: '-',
      referer: '-',
      userAgent: 'Mozilla/5.0',
      raw: '',
    }));
    const { hits } = scanSD(entries);
    assert.equal(hits.length, 0);
  });
});

// ── Filter Utility ────────────────────────────────────────────────────────────
describe('Filter Utility', () => {
  const makeEntry = (ip, status, path = '/') => ({
    ip,
    timestamp: Date.now(),
    method: 'GET',
    path,
    status,
    size: '-',
    referer: '-',
    userAgent: 'Mozilla/5.0',
    raw: '',
  });

  test('filters by exact IP', () => {
    const entries = [makeEntry('1.2.3.4', 200), makeEntry('9.8.7.6', 200)];
    const result = applyFilters(entries, { ip: '1.2.3.4' });
    assert.equal(result.length, 1);
    assert.equal(result[0].ip, '1.2.3.4');
  });

  test('filters by CIDR /24', () => {
    const entries = [
      makeEntry('192.168.1.10', 200),
      makeEntry('192.168.1.20', 200),
      makeEntry('10.0.0.1', 200),
    ];
    const result = applyFilters(entries, { ip: '192.168.1.0/24' });
    assert.equal(result.length, 2);
  });

  test('filters by status code', () => {
    const entries = [makeEntry('1.1.1.1', 200), makeEntry('2.2.2.2', 404), makeEntry('3.3.3.3', 404)];
    const result = applyFilters(entries, { status: 404 });
    assert.equal(result.length, 2);
  });

  test('filters by date range', () => {
    const base = Date.now();
    const entries = [
      { ...makeEntry('1.1.1.1', 200), timestamp: base - 10000 },
      { ...makeEntry('2.2.2.2', 200), timestamp: base },
      { ...makeEntry('3.3.3.3', 200), timestamp: base + 10000 },
    ];
    const result = applyFilters(entries, { since: base - 5000, until: base + 5000 });
    assert.equal(result.length, 1);
    assert.equal(result[0].ip, '2.2.2.2');
  });

  test('filters by path regex', () => {
    const entries = [
      makeEntry('1.1.1.1', 200, '/api/users'),
      makeEntry('2.2.2.2', 200, '/login'),
      makeEntry('3.3.3.3', 200, '/api/orders'),
    ];
    const result = applyFilters(entries, { pathPattern: '^/api/' });
    assert.equal(result.length, 2);
  });

  test('returns all entries when no filters provided', () => {
    const entries = [makeEntry('1.1.1.1', 200), makeEntry('2.2.2.2', 404)];
    assert.equal(applyFilters(entries, {}).length, 2);
    assert.equal(applyFilters(entries).length, 2);
  });
});

// ── CSV Reporter ──────────────────────────────────────────────────────────────
describe('CSV Reporter', () => {
  test('produces valid CSV with summary and IP sections', () => {
    const entries = [{
      ip: '8.8.8.8', timestamp: Date.now(), method: 'GET',
      path: "/?q=' OR 1=1", status: 200, size: '-',
      referer: '-', userAgent: 'curl/7.0', raw: '',
    }];
    const result = analyzeEntries(entries, 'test.log');
    const csv = toCSV(result);
    assert.ok(csv.includes('risk_level'), 'should have header');
    assert.ok(csv.includes('HIGH') || csv.includes('MEDIUM') || csv.includes('LOW'));
    assert.ok(csv.includes('rank,ip,hit_count,reason'));
  });

  test('CSV summary row has correct field count', () => {
    const result = analyzeEntries([], 'empty.log');
    const csv = toCSV(result);
    const lines = csv.split('\n').filter(l => l && !l.startsWith('#'));
    const headerLine = lines[0];
    const dataLine = lines[1];
    const headerCols = headerLine.split(',').length;
    const dataCols = dataLine.split(',').length;
    assert.equal(headerCols, dataCols, 'header and data must have same column count');
  });
});

// ── Plugin Architecture ────────────────────────────────────────────────────────
describe('Plugin Architecture', () => {
  test('custom plugin results are merged into report', () => {
    const entries = [{
      ip: '99.99.99.99', timestamp: Date.now(), method: 'GET',
      path: '/custom-threat', status: 200, size: '-',
      referer: '-', userAgent: 'Mozilla/5.0', raw: '',
    }];

    const customPlugin = {
      name: 'myCustomScanner',
      scan(ents) {
        const hits = ents.filter(e => e.path.includes('custom-threat'));
        const attackerIps = new Map();
        for (const h of hits) attackerIps.set(h.ip, (attackerIps.get(h.ip) || 0) + 1);
        return { hits, attackerIps };
      },
    };

    const result = analyzeEntries(entries, 'test', { plugins: [customPlugin] });
    assert.ok(result.threats.plugins, 'should have plugins field');
    assert.equal(result.threats.plugins.myCustomScanner, 1);
  });

  test('plugin error does not crash analyzer', () => {
    const entries = [];
    const brokenPlugin = {
      name: 'broken',
      scan() { throw new Error('plugin exploded'); },
    };
    assert.doesNotThrow(() => analyzeEntries(entries, 'test', { plugins: [brokenPlugin] }));
  });
});

// ── Risk Engine (scan_detection) ──────────────────────────────────────────────
describe('Risk Engine — scan_detection', () => {
  test('returns HIGH for large 404 flood', () => {
    assert.equal(
      calculateRisk({ bruteForce: 0, sqlInjection: 0, xss: 0, botActivity: 0, scanDetection: 25 }, 1000),
      'HIGH'
    );
  });

  test('returns MEDIUM for moderate scan activity', () => {
    assert.equal(
      calculateRisk({ bruteForce: 0, sqlInjection: 0, xss: 0, botActivity: 0, scanDetection: 10 }, 1000),
      'MEDIUM'
    );
  });
});
