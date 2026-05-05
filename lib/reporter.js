'use strict';

/**
 * Reporter
 *
 * Formats analysis results for terminal output (colored table)
 * or structured JSON output.
 */

/**
 * Format result as a JSON string.
 * @param {import('./analyzer').AnalysisResult} result
 * @returns {string}
 */
function toJSON(result) {
  return JSON.stringify(result, null, 2);
}

/**
 * Write JSON report to a file.
 * @param {import('./analyzer').AnalysisResult} result
 * @param {string} outputPath
 */
async function writeJSONReport(result, outputPath) {
  const fs = require('fs').promises;
  const path = require('path');
  const abs = path.resolve(outputPath);
  await fs.writeFile(abs, toJSON(result), 'utf8');
  return abs;
}

/**
 * Build a colored terminal report string.
 * chalk is loaded lazily so the module can be required even without it installed.
 * @param {import('./analyzer').AnalysisResult} result
 * @param {import('chalk').ChalkInstance} chalk
 * @returns {string}
 */
function toTerminal(result, chalk) {
  const c = chalk;
  const { summary, threats, top_attacker_ips, file, timestamp } = result;

  const riskColor = summary.risk_level === 'HIGH'
    ? c.red.bold
    : summary.risk_level === 'MEDIUM'
      ? c.yellow.bold
      : c.green.bold;

  const lines = [
    '',
    c.cyan.bold('╔══════════════════════════════════════════════╗'),
    c.cyan.bold('║          guardlog  Security Report           ║'),
    c.cyan.bold('╚══════════════════════════════════════════════╝'),
    '',
    `  ${c.bold('File:')}        ${file}`,
    `  ${c.bold('Scanned at:')} ${timestamp}`,
    '',
    c.cyan('  ── Summary ─────────────────────────────────'),
    `  Total requests    : ${c.white(summary.total_requests)}`,
    `  Suspicious        : ${summary.suspicious_requests > 0 ? c.yellow(summary.suspicious_requests) : c.green(summary.suspicious_requests)}`,
    `  Risk level        : ${riskColor(summary.risk_level)}`,
    '',
    c.cyan('  ── Threats Detected ─────────────────────────'),
    `  Brute force       : ${_threatNum(threats.brute_force, c)}`,
    `  SQL Injection     : ${_threatNum(threats.sql_injection, c)}`,
    `  XSS               : ${_threatNum(threats.xss, c)}`,
    `  Bot / Scanner     : ${_threatNum(threats.bot_activity, c)}`,
  ];

  if (top_attacker_ips.length > 0) {
    lines.push('');
    lines.push(c.cyan('  ── Top Attacker IPs ─────────────────────────'));
    for (const attacker of top_attacker_ips) {
      lines.push(`  ${c.red(attacker.ip.padEnd(18))} ${String(attacker.count).padStart(5)} hits  [${attacker.reason}]`);
    }
  }

  lines.push('');
  lines.push(c.cyan('────────────────────────────────────────────────'));
  lines.push('');

  return lines.join('\n');
}

function _threatNum(n, c) {
  if (n === 0) return c.green('0');
  if (n < 5) return c.yellow(String(n));
  return c.red.bold(String(n));
}

module.exports = { toJSON, toTerminal, writeJSONReport };
