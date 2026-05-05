'use strict';

/**
 * XSS (Cross-Site Scripting) Scanner
 *
 * Detects reflected XSS payloads in URL paths, query strings,
 * and User-Agent headers.
 */

const XSS_PATTERNS = [
  /<script[\s>]/i,
  /<\/script>/i,
  /javascript\s*:/i,
  /on\w+\s*=\s*["']?[^"'\s>]+/i,   // onerror=, onclick=, onload=, etc.
  /alert\s*\(/i,
  /confirm\s*\(/i,
  /prompt\s*\(/i,
  /eval\s*\(/i,
  /document\s*\.\s*cookie/i,
  /document\s*\.\s*write\s*\(/i,
  /window\s*\.\s*location/i,
  /<img[^>]+src\s*=\s*["']?\s*x/i,
  /expression\s*\(/i,
  /vbscript\s*:/i,
  /data\s*:\s*text\/html/i,
  /&#x?[0-9a-f]+;/i,               // HTML entity encoding used in evasion
  /%3Cscript/i,
  /%3C%2Fscript/i,
];

/**
 * @param {import('../parser').ParsedEntry[]} entries
 * @returns {{ hits: import('../parser').ParsedEntry[], attackerIps: Map<string, number> }}
 */
function scan(entries) {
  const hits = [];
  const attackerIps = new Map();

  for (const entry of entries) {
    const target = decodeURISafe(`${entry.path} ${entry.userAgent}`);
    if (XSS_PATTERNS.some(rx => rx.test(target))) {
      hits.push({ ...entry, threat: 'xss' });
      attackerIps.set(entry.ip, (attackerIps.get(entry.ip) || 0) + 1);
    }
  }

  return { hits, attackerIps };
}

function decodeURISafe(str) {
  try {
    return decodeURIComponent(str);
  } catch {
    return str;
  }
}

module.exports = { scan };
