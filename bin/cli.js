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
  .description(
    'Real-time CLI security log analyzer for Nginx, Apache, and API logs.\n' +
    'Detects brute force, SQL injection, XSS, bots, and directory scans.'
  )
  .version(PKG.version)
  .addHelpText('after', `
Commands:
  scan <file>        Analyze a log file for security threats
  monitor            Watch a log file in real-time (live tail mode)

Examples:
  Basic scan:
    $ guardlog scan /var/log/nginx/access.log

  Output formats:
    $ guardlog scan access.log --json
    $ guardlog scan access.log --csv
    $ guardlog scan access.log --output report.json
    $ guardlog scan access.log --output report.csv

  CI/CD gate (exit 1 on HIGH risk):
    $ guardlog scan access.log --ci

  Scan a gzipped rotated log:
    $ guardlog scan access.log.gz

  Filter traffic:
    $ guardlog scan access.log --filter-ip 192.168.1.55
    $ guardlog scan access.log --filter-ip 10.0.0.0/8
    $ guardlog scan access.log --filter-status 401
    $ guardlog scan access.log --since "2026-05-01T00:00:00Z" --until "2026-05-02T00:00:00Z"
    $ guardlog scan access.log --path-filter "^/api/"

  Webhook / Slack alert:
    $ guardlog scan access.log --webhook https://hooks.slack.com/services/T.../B.../xxx

  Live monitor mode:
    $ guardlog monitor --live /var/log/nginx/access.log

Docs: https://github.com/boniyeamincse/guardlog
`);

// ── scan command ────────────────────────────────────────────────────────────
program
  .command('scan <file>')
  .description(
    'Analyze a log file for security threats.\n' +
    'Supports plain text and gzipped (.gz) log files.\n' +
    'Formats: Apache/Nginx Combined Log Format, W3C/IIS Extended.'
  )
  .option('--json',                  'Print JSON report to stdout (machine-readable)')
  .option('--csv',                   'Print CSV report to stdout (spreadsheet-friendly)')
  .option('--output <path>',         'Save report to file (format auto-detected by extension: .json or .csv)')
  .option('--ci',                    'CI mode — exit code 1 when risk is HIGH, 0 when safe')
  .option('--filter-ip <ip>',        'Only include entries from this IP or CIDR range  e.g. 10.0.0.0/8')
  .option('--filter-status <code>',  'Only include entries with this HTTP status code  e.g. 401', parseInt)
  .option('--since <datetime>',      'Only include entries at or after this time  e.g. 2026-05-01T00:00:00Z')
  .option('--until <datetime>',      'Only include entries at or before this time  e.g. 2026-05-02T00:00:00Z')
  .option('--path-filter <pattern>', 'Only include entries whose URL path matches this regex  e.g. ^/api/')
  .option('--webhook <url>',         'POST the JSON report to this URL (Slack Incoming Webhooks supported)')
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
  .description(
    'Watch a log file in real-time and report threats as new entries arrive.\n' +
    'Works like tail -f — press Ctrl+C to stop.'
  )
  .requiredOption('--live <file>', 'Path to the log file to watch')
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
