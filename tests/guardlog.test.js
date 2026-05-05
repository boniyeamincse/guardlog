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
