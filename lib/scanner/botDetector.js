'use strict';

/**
 * Bot / Suspicious Traffic Detector
 *
 * Detects automated scanners, scrapers, and vulnerability scanners based on:
 * - Known bad User-Agent strings
 * - Missing / empty User-Agent
 * - High-frequency requests from a single IP
 * - Scanner-typical path probing
 */

const BAD_UA_PATTERNS = [
  /python-requests/i,
  /python-urllib/i,
  /libwww-perl/i,
  /curl\//i,
  /wget\//i,
  /scrapy/i,
  /nikto/i,
  /sqlmap/i,
  /masscan/i,
  /nmap/i,
  /zgrab/i,
  /dirbuster/i,
  /gobuster/i,
  /wfuzz/i,
  /nuclei/i,
  /hydra/i,
  /medusa/i,
  /burpsuite/i,
  /owasp\s*zap/i,
  /acunetix/i,
  /nessus/i,
  /openvas/i,
  /shodan/i,
  /censys/i,
];

const SCANNER_PATHS = [
  /\.env$/i,
  /wp-config\.php/i,
  /phpinfo\.php/i,
  /\.git\//i,
  /\.svn\//i,
  /etc\/passwd/i,
  /proc\/self/i,
  /\/admin\//i,
  /\/phpmyadmin/i,
  /\/config\//i,
  /\/backup/i,
  /\/shell/i,
  /\/cmd/i,
];

const HIGH_FREQ_THRESHOLD = 200; // requests per minute per IP
const TIME_WINDOW_MS = 60_000;

/**
 * @param {import('../parser').ParsedEntry[]} entries
 * @returns {{ hits: import('../parser').ParsedEntry[], attackerIps: Map<string, number> }}
 */
function scan(entries) {
  const hits = [];
  const attackerIps = new Map();

  // UA and path-based detection
  for (const entry of entries) {
    const isBadUA = !entry.userAgent || entry.userAgent === '-'
      || BAD_UA_PATTERNS.some(rx => rx.test(entry.userAgent));
    const isScannerPath = SCANNER_PATHS.some(rx => rx.test(entry.path));

    if (isBadUA || isScannerPath) {
      hits.push({ ...entry, threat: 'bot_activity' });
      attackerIps.set(entry.ip, (attackerIps.get(entry.ip) || 0) + 1);
    }
  }

  // High-frequency IP detection
  const ipBuckets = new Map();
  for (const entry of entries) {
    if (!ipBuckets.has(entry.ip)) ipBuckets.set(entry.ip, []);
    ipBuckets.get(entry.ip).push(entry);
  }

  for (const [ip, bucket] of ipBuckets) {
    const maxInWindow = _slidingWindowCount(bucket, TIME_WINDOW_MS);
    if (maxInWindow >= HIGH_FREQ_THRESHOLD) {
      for (const e of bucket) {
        if (!hits.find(h => h.ip === e.ip && h.path === e.path && h.timestamp === e.timestamp)) {
          hits.push({ ...e, threat: 'bot_activity' });
        }
      }
      attackerIps.set(ip, (attackerIps.get(ip) || 0) + maxInWindow);
    }
  }

  return { hits, attackerIps };
}

function _slidingWindowCount(entries, windowMs) {
  if (entries.length === 0) return 0;
  const sorted = [...entries].sort((a, b) => a.timestamp - b.timestamp);
  let max = 0, left = 0;
  for (let right = 0; right < sorted.length; right++) {
    while (sorted[right].timestamp - sorted[left].timestamp > windowMs) left++;
    max = Math.max(max, right - left + 1);
  }
  return max;
}

module.exports = { scan };
