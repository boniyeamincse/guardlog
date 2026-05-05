'use strict';

/**
 * Brute Force Attack Scanner
 *
 * Detects repeated failed login attempts from the same IP and
 * high-frequency bursts targeting any endpoint within a time window.
 */

const LOGIN_ENDPOINTS = ['/login', '/signin', '/auth', '/wp-login.php', '/admin', '/api/login', '/api/auth'];
const FAILURE_STATUS_CODES = new Set([401, 403, 429]);

// Thresholds
const BRUTE_FORCE_THRESHOLD = 10;   // failed requests per window
const BURST_THRESHOLD = 100;         // any requests per window
const TIME_WINDOW_MS = 60_000;       // 1 minute

/**
 * @param {import('../parser').ParsedEntry[]} entries
 * @returns {{ hits: import('../parser').ParsedEntry[], attackerIps: Map<string, number> }}
 */
function scan(entries) {
  /** @type {Map<string, { failures: import('../parser').ParsedEntry[], all: import('../parser').ParsedEntry[] }>} */
  const ipBuckets = new Map();

  for (const entry of entries) {
    if (!ipBuckets.has(entry.ip)) {
      ipBuckets.set(entry.ip, { failures: [], all: [] });
    }
    const bucket = ipBuckets.get(entry.ip);
    bucket.all.push(entry);

    const isLoginPath = LOGIN_ENDPOINTS.some(ep => entry.path.startsWith(ep));
    if (isLoginPath && FAILURE_STATUS_CODES.has(entry.status)) {
      bucket.failures.push(entry);
    }
  }

  const hits = [];
  const attackerIps = new Map();

  for (const [ip, bucket] of ipBuckets) {
    // Sliding-window brute force check on login failures
    const bruteCount = _slidingWindowCount(bucket.failures, TIME_WINDOW_MS);
    if (bruteCount >= BRUTE_FORCE_THRESHOLD) {
      for (const e of bucket.failures) hits.push({ ...e, threat: 'brute_force' });
      attackerIps.set(ip, (attackerIps.get(ip) || 0) + bruteCount);
    }

    // High-frequency burst check (any endpoint)
    const burstCount = _slidingWindowCount(bucket.all, TIME_WINDOW_MS);
    if (burstCount >= BURST_THRESHOLD) {
      for (const e of bucket.all) {
        if (!hits.find(h => h === e)) hits.push({ ...e, threat: 'brute_force' });
      }
      attackerIps.set(ip, (attackerIps.get(ip) || 0) + burstCount);
    }
  }

  return { hits, attackerIps };
}

/**
 * Returns the maximum number of events within any TIME_WINDOW_MS span.
 * @param {import('../parser').ParsedEntry[]} entries
 * @param {number} windowMs
 * @returns {number}
 */
function _slidingWindowCount(entries, windowMs) {
  if (entries.length === 0) return 0;
  const sorted = [...entries].sort((a, b) => a.timestamp - b.timestamp);
  let max = 0;
  let left = 0;
  for (let right = 0; right < sorted.length; right++) {
    while (sorted[right].timestamp - sorted[left].timestamp > windowMs) left++;
    max = Math.max(max, right - left + 1);
  }
  return max;
}

module.exports = { scan };
