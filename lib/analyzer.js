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
const scanDetector = require('./scanner/scanDetector');
const { applyFilters } = require('../utils/filter');

/**
 * Analyze a log file.
 *
 * @param {string} filePath
 * @param {{
 *   onProgress?: (count: number) => void,
 *   filters?: import('../utils/filter').FilterOptions,
 *   plugins?: Array<{ name: string, scan: Function }>
 * }} [opts]
 * @returns {Promise<AnalysisResult>}
 */
async function analyzeFile(filePath, opts = {}) {
  const entries = [];
  const { total, parsed } = await parser.parseFile(filePath, entry => {
    entries.push(entry);
    if (opts.onProgress) opts.onProgress(entries.length);
  });

  const filtered = opts.filters ? applyFilters(entries, opts.filters) : entries;
  return _runScanners(filtered, { file: filePath, totalLines: total, parsedLines: filtered.length }, opts.plugins);
}

/**
 * Analyze an already-loaded array of entries (used by live monitor).
 * @param {import('./parser').ParsedEntry[]} entries
 * @param {string} [source]
 * @param {{
 *   filters?: import('../utils/filter').FilterOptions,
 *   plugins?: Array<{ name: string, scan: Function }>
 * }} [opts]
 * @returns {AnalysisResult}
 */
function analyzeEntries(entries, source = '<stream>', opts = {}) {
  const filtered = opts.filters ? applyFilters(entries, opts.filters) : entries;
  return _runScanners(filtered, { file: source, totalLines: entries.length, parsedLines: filtered.length }, opts.plugins);
}

/**
 * @param {import('./parser').ParsedEntry[]} entries
 * @param {{ file: string, totalLines: number, parsedLines: number }} meta
 * @param {Array<{ name: string, scan: Function }>} [plugins]
 * @returns {AnalysisResult}
 */
function _runScanners(entries, meta, plugins = []) {
  const bfResult = bruteForce.scan(entries);
  const sqlResult = sqlInjection.scan(entries);
  const xssResult = xss.scan(entries);
  const botResult = botDetector.scan(entries);
  const sdResult = scanDetector.scan(entries);

  const threats = {
    bruteForce: bfResult.attackerIps.size > 0 ? _uniqueHits(bfResult.hits) : 0,
    sqlInjection: _uniqueHits(sqlResult.hits),
    xss: _uniqueHits(xssResult.hits),
    botActivity: _uniqueHits(botResult.hits),
    scanDetection: _uniqueHits(sdResult.hits),
  };

  // Run optional external plugins
  const pluginAttackerIps = new Map();
  const pluginThreatCounts = {};
  for (const plugin of (plugins || [])) {
    try {
      const result = plugin.scan(entries);
      pluginThreatCounts[plugin.name] = _uniqueHits(result.hits || []);
      for (const [ip, count] of (result.attackerIps || new Map())) {
        const ex = pluginAttackerIps.get(ip) || { count: 0, reasons: new Set() };
        ex.count += count;
        ex.reasons.add(plugin.name);
        pluginAttackerIps.set(ip, ex);
      }
    } catch (err) {
      process.stderr.write(`guardlog: plugin "${plugin.name}" error: ${err.message}\n`);
    }
  }

  // Merge attacker IP maps
  const allAttackerIps = new Map();
  for (const [map, reason] of [
    [bfResult.attackerIps, 'brute_force'],
    [sqlResult.attackerIps, 'sql_injection'],
    [xssResult.attackerIps, 'xss'],
    [botResult.attackerIps, 'bot_activity'],
    [sdResult.attackerIps, 'scan_detection'],
  ]) {
    for (const [ip, count] of map) {
      const existing = allAttackerIps.get(ip) || { count: 0, reasons: new Set() };
      existing.count += count;
      existing.reasons.add(reason);
      allAttackerIps.set(ip, existing);
    }
  }
  for (const [ip, data] of pluginAttackerIps) {
    const existing = allAttackerIps.get(ip) || { count: 0, reasons: new Set() };
    existing.count += data.count;
    for (const r of data.reasons) existing.reasons.add(r);
    allAttackerIps.set(ip, existing);
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
      scan_detection: threats.scanDetection,
      ...(Object.keys(pluginThreatCounts).length ? { plugins: pluginThreatCounts } : {}),
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
 * @property {{ brute_force: number, sql_injection: number, xss: number, bot_activity: number, scan_detection: number }} threats
 * @property {Array<{ ip: string, count: number, reason: string }>} top_attacker_ips
 * @property {string} timestamp
 */

module.exports = { analyzeFile, analyzeEntries };
