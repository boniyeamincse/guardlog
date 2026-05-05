'use strict';

/**
 * Log Entry Filter
 *
 * Filters a stream of parsed log entries by:
 *   - IP address (exact match or IPv4 CIDR notation, e.g. 192.168.1.0/24)
 *   - HTTP status code
 *   - Date range (since / until as ISO 8601 strings or Unix ms)
 *   - URL path regex pattern
 *
 * All filters are ANDed together — an entry must pass every active filter
 * to be included in the result.
 */

/**
 * @typedef {Object} FilterOptions
 * @property {string}          [ip]          Exact IP or CIDR (e.g. "10.0.0.0/8")
 * @property {number|string}   [status]      HTTP status code to keep (e.g. 404)
 * @property {string|number}   [since]       ISO date string or Unix ms — keep entries >= this
 * @property {string|number}   [until]       ISO date string or Unix ms — keep entries <= this
 * @property {string}          [pathPattern] Regex string applied to entry.path
 */

/**
 * Apply filters to an array of parsed entries.
 *
 * @param {import('../lib/parser').ParsedEntry[]} entries
 * @param {FilterOptions} filters
 * @returns {import('../lib/parser').ParsedEntry[]}
 */
function applyFilters(entries, filters = {}) {
  if (!filters || Object.keys(filters).length === 0) return entries;

  const { ip, status, since, until, pathPattern } = filters;

  // Pre-compile regex once
  const pathRx = pathPattern ? new RegExp(pathPattern, 'i') : null;

  // Parse time bounds once
  const sinceMs = since != null ? _parseTime(since) : null;
  const untilMs = until != null ? _parseTime(until) : null;

  // Pre-parse CIDR once
  const cidrSpec = ip ? _parseCIDR(ip) : null;

  return entries.filter(entry => {
    if (cidrSpec && !_ipMatchesCIDR(entry.ip, cidrSpec)) return false;
    if (status != null && entry.status !== Number(status)) return false;
    if (sinceMs != null && entry.timestamp < sinceMs) return false;
    if (untilMs != null && entry.timestamp > untilMs) return false;
    if (pathRx && !pathRx.test(entry.path)) return false;
    return true;
  });
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Parse a time value (ISO string or Unix ms number/string) → ms.
 * @param {string|number} val
 * @returns {number}
 */
function _parseTime(val) {
  if (typeof val === 'number') return val;
  const n = Number(val);
  if (!Number.isNaN(n)) return n;
  const d = new Date(val);
  if (Number.isNaN(d.getTime())) throw new Error(`Invalid date: "${val}"`);
  return d.getTime();
}

/**
 * @typedef {{ baseInt: number, mask: number, isCIDR: boolean }} CIDRSpec
 * @param {string} ipOrCIDR
 * @returns {CIDRSpec}
 */
function _parseCIDR(ipOrCIDR) {
  const slashIdx = ipOrCIDR.indexOf('/');
  if (slashIdx === -1) {
    return { baseInt: _ipToInt(ipOrCIDR), mask: 0xFFFFFFFF, isCIDR: false };
  }
  const base = ipOrCIDR.slice(0, slashIdx);
  const bits = parseInt(ipOrCIDR.slice(slashIdx + 1), 10);
  if (Number.isNaN(bits) || bits < 0 || bits > 32) {
    throw new Error(`Invalid CIDR prefix length: "${ipOrCIDR}"`);
  }
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return { baseInt: (_ipToInt(base) & mask) >>> 0, mask, isCIDR: true };
}

/**
 * @param {string} ip
 * @param {CIDRSpec} spec
 * @returns {boolean}
 */
function _ipMatchesCIDR(ip, spec) {
  try {
    return ((_ipToInt(ip) & spec.mask) >>> 0) === spec.baseInt;
  } catch {
    return false;
  }
}

/**
 * Convert dotted-decimal IPv4 string to a 32-bit unsigned integer.
 * @param {string} ip
 * @returns {number}
 */
function _ipToInt(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) throw new Error(`Not an IPv4 address: "${ip}"`);
  return parts.reduce((acc, oct) => {
    const n = parseInt(oct, 10);
    if (n < 0 || n > 255) throw new Error(`Invalid octet: ${n}`);
    return ((acc << 8) | n) >>> 0;
  }, 0);
}

module.exports = { applyFilters };
