'use strict';

/**
 * Analyzer
 *
 * Orchestrates all scanners over a stream of parsed log entries.
 * Supports both file-based and live/stdin streaming modes.
 */

const parser = require('./parser');
const bruteForce = require('./scanner/bruteForce');
const sqlInjection = require('./scanner/sqlInjection');
const xss = require('./scanner/xss');
const botDetector = require('./scanner/botDetector');
const { calculateRisk } = require('../utils/riskEngine');

/**
 * Analyze a log file.
 *
 * @param {string} filePath
 * @param {{ onProgress?: (count: number) => void }} [opts]
 * @returns {Promise<AnalysisResult>}
 */
async function analyzeFile(filePath, opts = {}) {
  const entries = [];
  const { total, parsed } = await parser.parseFile(filePath, entry => {
    entries.push(entry);
    if (opts.onProgress) opts.onProgress(entries.length);
  });

  return _runScanners(entries, { file: filePath, totalLines: total, parsedLines: parsed });
}

/**
 * Analyze an already-loaded array of entries (used by live monitor).
 * @param {import('./parser').ParsedEntry[]} entries
 * @param {string} [source]
 * @returns {AnalysisResult}
 */
function analyzeEntries(entries, source = '<stream>') {
  return _runScanners(entries, { file: source, totalLines: entries.length, parsedLines: entries.length });
}

/**
 * @param {import('./parser').ParsedEntry[]} entries
 * @param {{ file: string, totalLines: number, parsedLines: number }} meta
 * @returns {AnalysisResult}
 */
function _runScanners(entries, meta) {
  const bfResult = bruteForce.scan(entries);
  const sqlResult = sqlInjection.scan(entries);
  const xssResult = xss.scan(entries);
  const botResult = botDetector.scan(entries);

  const threats = {
    bruteForce: bfResult.attackerIps.size > 0 ? _uniqueHits(bfResult.hits) : 0,
    sqlInjection: _uniqueHits(sqlResult.hits),
    xss: _uniqueHits(xssResult.hits),
    botActivity: _uniqueHits(botResult.hits),
  };

  // Merge attacker IP maps
  const allAttackerIps = new Map();
  for (const [map, reason] of [
    [bfResult.attackerIps, 'brute_force'],
    [sqlResult.attackerIps, 'sql_injection'],
    [xssResult.attackerIps, 'xss'],
    [botResult.attackerIps, 'bot_activity'],
  ]) {
    for (const [ip, count] of map) {
      const existing = allAttackerIps.get(ip) || { count: 0, reasons: new Set() };
      existing.count += count;
      existing.reasons.add(reason);
      allAttackerIps.set(ip, existing);
    }
  }

  const topAttackerIps = [...allAttackerIps.entries()]
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, 10)
    .map(([ip, data]) => ({
      ip,
      count: data.count,
      reason: [...data.reasons].join(', '),
    }));

  const totalSuspicious = Object.values(threats).reduce((a, b) => a + b, 0);
  const riskLevel = calculateRisk(threats, meta.parsedLines);

  return {
    file: meta.file,
    summary: {
      total_requests: meta.parsedLines,
      suspicious_requests: totalSuspicious,
      risk_level: riskLevel,
    },
    threats: {
      brute_force: threats.bruteForce,
      sql_injection: threats.sqlInjection,
      xss: threats.xss,
      bot_activity: threats.botActivity,
    },
    top_attacker_ips: topAttackerIps,
    timestamp: new Date().toISOString(),
  };
}

function _uniqueHits(hits) {
  return hits.length;
}

/**
 * @typedef {Object} AnalysisResult
 * @property {string} file
 * @property {{ total_requests: number, suspicious_requests: number, risk_level: string }} summary
 * @property {{ brute_force: number, sql_injection: number, xss: number, bot_activity: number }} threats
 * @property {Array<{ ip: string, count: number, reason: string }>} top_attacker_ips
 * @property {string} timestamp
 */

module.exports = { analyzeFile, analyzeEntries };
