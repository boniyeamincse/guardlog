'use strict';

/**
 * Log Parser
 *
 * Parses Apache/Nginx Combined Log Format lines into structured objects.
 * Uses streaming to avoid loading the entire file into memory.
 *
 * Combined Log Format:
 *   %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"
 *
 * Example:
 *   192.168.1.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"
 */

const fs = require('fs');
const readline = require('readline');
const path = require('path');

// Regex for Apache/Nginx Combined Log Format
const COMBINED_LOG_RE = /^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?/;

// W3C / IIS log format (space-separated fields with a header)
const W3C_LOG_RE = /^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d{3})\s+(\S+)/;

/**
 * @typedef {Object} ParsedEntry
 * @property {string} ip
 * @property {number} timestamp  - Unix ms
 * @property {string} method
 * @property {string} path
 * @property {number} status
 * @property {string} size
 * @property {string} referer
 * @property {string} userAgent
 * @property {string} raw
 * @property {string} [threat]   - set by scanners
 */

/**
 * Parse a single log line.
 * Returns null if the line cannot be parsed.
 * @param {string} line
 * @returns {ParsedEntry|null}
 */
function parseLine(line) {
  if (!line || line.startsWith('#')) return null;

  const m = COMBINED_LOG_RE.exec(line);
  if (m) {
    return {
      ip: m[1],
      timestamp: parseApacheDate(m[2]),
      method: m[3],
      path: m[4],
      status: parseInt(m[5], 10),
      size: m[6],
      referer: m[7] || '-',
      userAgent: m[8] || '-',
      raw: line,
    };
  }

  // Fallback: W3C / IIS format
  const w = W3C_LOG_RE.exec(line);
  if (w) {
    return {
      ip: w[3],
      timestamp: new Date(`${w[1]}T${w[2]}Z`).getTime(),
      method: w[5],
      path: w[6],
      status: parseInt(w[7], 10),
      size: w[8],
      referer: '-',
      userAgent: '-',
      raw: line,
    };
  }

  return null;
}

/**
 * Parse Apache/Nginx date string: "10/Oct/2000:13:55:36 -0700"
 * @param {string} str
 * @returns {number} Unix ms
 */
function parseApacheDate(str) {
  // "10/Oct/2000:13:55:36 -0700"
  const re = /(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s+([+-]\d{4})/;
  const m = re.exec(str);
  if (!m) return Date.now();

  const months = { Jan:0,Feb:1,Mar:2,Apr:3,May:4,Jun:5,Jul:6,Aug:7,Sep:8,Oct:9,Nov:10,Dec:11 };
  const tzSign = m[7][0] === '+' ? 1 : -1;
  const tzHours = parseInt(m[7].slice(1, 3), 10);
  const tzMins = parseInt(m[7].slice(3, 5), 10);
  const tzOffsetMs = tzSign * (tzHours * 60 + tzMins) * 60_000;

  const utc = Date.UTC(
    parseInt(m[3], 10),
    months[m[2]],
    parseInt(m[1], 10),
    parseInt(m[4], 10),
    parseInt(m[5], 10),
    parseInt(m[6], 10)
  );
  return utc - tzOffsetMs;
}

/**
 * Stream-parse a log file.
 * Calls onEntry for each successfully parsed line.
 *
 * @param {string} filePath
 * @param {(entry: ParsedEntry) => void} onEntry
 * @returns {Promise<{ total: number, parsed: number }>}
 */
function parseFile(filePath, onEntry) {
  return new Promise((resolve, reject) => {
    const absPath = path.resolve(filePath);
    const stream = fs.createReadStream(absPath, { encoding: 'utf8' });
    const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });

    let total = 0;
    let parsed = 0;

    rl.on('line', line => {
      total++;
      const entry = parseLine(line);
      if (entry) {
        parsed++;
        onEntry(entry);
      }
    });

    rl.on('close', () => resolve({ total, parsed }));
    rl.on('error', reject);
    stream.on('error', reject);
  });
}

module.exports = { parseLine, parseFile, parseApacheDate };
