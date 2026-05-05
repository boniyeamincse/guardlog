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
const { toJSON, toTerminal, writeJSONReport } = require('../lib/reporter');
const { riskScore } = require('../utils/riskEngine');
const { monitor } = require('../lib/monitor');

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
  .option('--output <path>', 'Write JSON report to a file')
  .option('--ci', 'CI mode: exit code 1 if risk is HIGH')
  .action(async (file, opts) => {
    const absFile = path.resolve(file);

    if (!fs.existsSync(absFile)) {
      console.error(`guardlog: file not found: ${absFile}`);
      process.exit(2);
    }

    try {
      const chalk = await getChalk();

      if (!opts.json && !opts.output) {
        process.stdout.write(chalk.dim(`Scanning ${absFile} …\n`));
      }

      let lastPrint = 0;
      const result = await analyzeFile(absFile, {
        onProgress: (count) => {
          if (!opts.json && !opts.output && Date.now() - lastPrint > 500) {
            process.stdout.write(chalk.dim(`\r  Processed ${count} entries…`));
            lastPrint = Date.now();
          }
        },
      });

      if (!opts.json && !opts.output) process.stdout.write('\r\x1b[K');

      // -- output --
      if (opts.json) {
        process.stdout.write(toJSON(result) + '\n');
      } else if (opts.output) {
        const dest = await writeJSONReport(result, opts.output);
        const chalk2 = await getChalk();
        console.log(chalk2.green(`Report written to ${dest}`));
      } else {
        console.log(toTerminal(result, chalk));
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
