#!/usr/bin/env node
'use strict';

/**
 * guardlog CLI
 *
 * Usage:
 *   guardlog scan <file>
 *   guardlog scan <file> --json
 *   guardlog scan <file> --output report.json
 *   guardlog scan <file> --ci
 *   guardlog monitor --live <file>
 */

const { program } = require('commander');
const path = require('path');
const fs = require('fs');
const { createRequire } = require('module');

// Lazy-load chalk (ESM-only in v5) using dynamic import wrapper
let _chalk = null;
async function getChalk() {
  if (_chalk) return _chalk;
  const { default: chalk } = await import('chalk');
  _chalk = chalk;
  return chalk;
}

const { analyzeFile } = require('../lib/analyzer');
const { toJSON, toTerminal, writeJSONReport, toCSV, writeCSVReport } = require('../lib/reporter');
const { riskScore } = require('../utils/riskEngine');
const { monitor } = require('../lib/monitor');
const { send: sendWebhook } = require('../utils/webhook');

const PKG = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8')
);

program
  .name('guardlog')
  .description('Real-time CLI security log analyzer')
  .version(PKG.version);

// ── scan command ────────────────────────────────────────────────────────────
program
  .command('scan <file>')
  .description('Analyze a log file for security threats')
  .option('--json', 'Output raw JSON report to stdout')
  .option('--csv', 'Output CSV report to stdout')
  .option('--output <path>', 'Write JSON report to a file')
  .option('--ci', 'CI mode: exit code 1 if risk is HIGH')
  .option('--filter-ip <ip>', 'Only analyze entries from this IP or CIDR (e.g. 10.0.0.0/8)')
  .option('--filter-status <code>', 'Only analyze entries with this HTTP status code', parseInt)
  .option('--since <datetime>', 'Entries at or after this time (ISO 8601 or Unix ms)')
  .option('--until <datetime>', 'Entries at or before this time (ISO 8601 or Unix ms)')
  .option('--path-filter <pattern>', 'Only analyze entries whose path matches this regex')
  .option('--webhook <url>', 'POST the JSON report to this URL after scanning')
  .action(async (file, opts) => {
    const absFile = path.resolve(file);

    if (!fs.existsSync(absFile)) {
      console.error(`guardlog: file not found: ${absFile}`);
      process.exit(2);
    }

    try {
      const chalk = await getChalk();

      if (!opts.json && !opts.csv && !opts.output) {
        process.stdout.write(chalk.dim(`Scanning ${absFile} …\n`));
      }

      const filters = {};
      if (opts.filterIp) filters.ip = opts.filterIp;
      if (opts.filterStatus != null) filters.status = opts.filterStatus;
      if (opts.since) filters.since = opts.since;
      if (opts.until) filters.until = opts.until;
      if (opts.pathFilter) filters.pathPattern = opts.pathFilter;

      let lastPrint = 0;
      const result = await analyzeFile(absFile, {
        onProgress: (count) => {
          if (!opts.json && !opts.csv && !opts.output && Date.now() - lastPrint > 500) {
            process.stdout.write(chalk.dim(`\r  Processed ${count} entries…`));
            lastPrint = Date.now();
          }
        },
        filters: Object.keys(filters).length ? filters : undefined,
      });

      if (!opts.json && !opts.csv && !opts.output) process.stdout.write('\r\x1b[K');

      // -- output --
      if (opts.json) {
        process.stdout.write(toJSON(result) + '\n');
      } else if (opts.csv) {
        process.stdout.write(toCSV(result));
      } else if (opts.output) {
        const isCsv = opts.output.toLowerCase().endsWith('.csv');
        const dest = isCsv
          ? await writeCSVReport(result, opts.output)
          : await writeJSONReport(result, opts.output);
        console.log(chalk.green(`Report written to ${dest}`));
      } else {
        console.log(toTerminal(result, chalk));
      }

      if (opts.webhook) {
        try {
          const { status } = await sendWebhook(opts.webhook, result);
          console.log(chalk.dim(`Webhook delivered (HTTP ${status})`));
        } catch (whErr) {
          console.error(chalk.yellow(`Webhook failed: ${whErr.message}`));
        }
      }

      // -- CI exit code --
      if (opts.ci && riskScore(result.summary.risk_level) >= 2) {
        process.exit(1);
      }
    } catch (err) {
      console.error(`guardlog error: ${err.message}`);
      process.exit(2);
    }
  });

// ── monitor command ──────────────────────────────────────────────────────────
program
  .command('monitor')
  .description('Watch a log file in real-time for threats')
  .requiredOption('--live <file>', 'Log file to watch')
  .action(async (opts) => {
    const absFile = path.resolve(opts.live);

    if (!fs.existsSync(absFile)) {
      console.error(`guardlog: file not found: ${absFile}`);
      process.exit(2);
    }

    const chalk = await getChalk();
    console.log(chalk.cyan(`\nguardlog live monitor active → ${absFile}`));
    console.log(chalk.dim('  Watching for new log entries… (Ctrl+C to stop)\n'));

    const controller = new AbortController();
    process.on('SIGINT', () => {
      console.log(chalk.dim('\n\nStopped monitoring.'));
      controller.abort();
      process.exit(0);
    });

    monitor(absFile, {
      signal: controller.signal,
      onResult: (result) => {
        if (result.summary.suspicious_requests === 0) return;
        console.log(chalk.dim(`[${new Date().toISOString()}] New batch analyzed:`));
        console.log(toTerminal(result, chalk));
      },
    });
  });

program.parse(process.argv);
