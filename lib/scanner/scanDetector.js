'use strict';

/**
 * 404 Flood / Directory Brute Force Scanner
 *
 * Detects automated directory/file enumeration attacks by identifying IPs
 * that generate an abnormally high number of 404 (Not Found) responses
 * within a sliding time window — a classic signature of tools like
 * dirbuster, gobuster, ffuf, and wfuzz.
 *
 * Also detects sequential path-probe patterns common in scanners.
 */

const NOT_FOUND_THRESHOLD = 20;    // 404s per window to flag
const TIME_WINDOW_MS = 60_000;     // 1 minute

// Known scanner-typical path probe patterns
const SCAN_PATH_PATTERNS = [
  /\.(bak|old|orig|backup|copy|tmp|swp|sql|zip|tar|gz|rar|7z)$/i,
  /\.(php|asp|aspx|jsp|cgi|pl|py|rb|sh|bash)~$/i,
  /\/\.env($|\/)/i,
  /\/\.env\./i,
  /^\/\.env$/i,
  /wp-config\.php/i,
  /phpinfo\.php/i,
  /\/\.git\//i,
  /\/wp-admin\//i,
  /\/wp-includes\//i,
  /\/wp-content\//i,
  /\/manager\//i,
  /\/console\//i,
  /\/actuator\//i,
  /\/\.well-known\//i,
  /\/cgi-bin\//i,
  /\/server-status/i,
  /\/server-info/i,
  /\/crossdomain\.xml/i,
  /\/sitemap\.xml/i,
  /\/robots\.txt/i,
];

/**
 * @param {import('../parser').ParsedEntry[]} entries
 * @returns {{ hits: import('../parser').ParsedEntry[], attackerIps: Map<string, number> }}
 */
function scan(entries) {
  const hits = [];
  const attackerIps = new Map();

  /** @type {Map<string, import('../parser').ParsedEntry[]>} */
  const ipNotFoundBuckets = new Map();

  for (const entry of entries) {
    // Collect 404s per IP for sliding-window check
    if (entry.status === 404) {
      if (!ipNotFoundBuckets.has(entry.ip)) ipNotFoundBuckets.set(entry.ip, []);
      ipNotFoundBuckets.get(entry.ip).push(entry);
    }

    // Immediate flag for scan-typical path probes
    if (SCAN_PATH_PATTERNS.some(rx => rx.test(entry.path))) {
      hits.push({ ...entry, threat: 'scan_detection' });
      attackerIps.set(entry.ip, (attackerIps.get(entry.ip) || 0) + 1);
    }
  }

  // Sliding-window 404 flood check
  for (const [ip, bucket] of ipNotFoundBuckets) {
    const maxInWindow = _slidingWindowCount(bucket, TIME_WINDOW_MS);
    if (maxInWindow >= NOT_FOUND_THRESHOLD) {
      for (const e of bucket) {
        hits.push({ ...e, threat: 'scan_detection' });
      }
      attackerIps.set(ip, (attackerIps.get(ip) || 0) + maxInWindow);
    }
  }

  return { hits, attackerIps };
}

/**
 * @param {import('../parser').ParsedEntry[]} entries
 * @param {number} windowMs
 * @returns {number}
 */
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
