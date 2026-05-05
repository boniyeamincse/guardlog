'use strict';

/**
 * SQL Injection Scanner
 *
 * Detects common SQL injection payloads in URL paths, query strings,
 * and User-Agent headers.
 */

const SQL_PATTERNS = [
  /(\%27)|(\')|(\-\-)|(\%23)|(#)/i,
  /\b(OR|AND)\b\s+[\w\d]+\s*=\s*[\w\d]+/i,
  /\bUNION\b.*\bSELECT\b/i,
  /\bSELECT\b.*\bFROM\b/i,
  /\bINSERT\b.*\bINTO\b/i,
  /\bDROP\b.*\b(TABLE|DATABASE)\b/i,
  /\bDELETE\b.*\bFROM\b/i,
  /\bUPDATE\b.*\bSET\b/i,
  /\bEXEC(\s|\+)+(s|x)p\w+/i,
  /\bCAST\s*\(/i,
  /\bCONVERT\s*\(/i,
  /\bSLEEP\s*\(\d+\)/i,
  /\bBENCHMARK\s*\(/i,
  /\bWAITFOR\b/i,
  /\bINFORMATION_SCHEMA\b/i,
  /(\%3D)|(=).*(\%27)|(=).*\'/i,
  /\bxp_cmdshell\b/i,
  /\bsp_executesql\b/i,
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
    if (SQL_PATTERNS.some(rx => rx.test(target))) {
      hits.push({ ...entry, threat: 'sql_injection' });
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
