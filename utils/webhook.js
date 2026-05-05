'use strict';

/**
 * Webhook Alert Utility
 *
 * Sends a guardlog analysis result as a JSON POST to a webhook URL.
 * Uses only Node.js built-in http/https modules — zero external dependencies.
 *
 * Compatible with:
 *   - Slack Incoming Webhooks
 *   - Generic HTTP/HTTPS endpoints
 *   - Discord webhooks (JSON body format)
 *   - Custom alerting endpoints
 */

const https = require('https');
const http = require('http');
const { URL } = require('url');

/**
 * Post an analysis result to a webhook URL.
 *
 * For Slack webhooks the payload is wrapped in { text, attachments }.
 * For all other URLs the raw JSON report is posted as the body.
 *
 * @param {string} webhookUrl
 * @param {import('../lib/analyzer').AnalysisResult} result
 * @param {{ timeout?: number, slackFormat?: boolean }} [opts]
 * @returns {Promise<{ status: number, body: string }>}
 */
function send(webhookUrl, result, opts = {}) {
  const { timeout = 10_000, slackFormat = false } = opts;

  return new Promise((resolve, reject) => {
    let parsedUrl;
    try {
      parsedUrl = new URL(webhookUrl);
    } catch {
      return reject(new Error(`Invalid webhook URL: "${webhookUrl}"`));
    }

    const isSlack = slackFormat ||
      parsedUrl.hostname.endsWith('hooks.slack.com') ||
      parsedUrl.pathname.startsWith('/services/');

    const body = isSlack
      ? JSON.stringify(_buildSlackPayload(result))
      : JSON.stringify(result, null, 2);

    const options = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
        'User-Agent': 'guardlog/1.1.0',
      },
    };

    const transport = parsedUrl.protocol === 'https:' ? https : http;

    const req = transport.request(options, res => {
      let responseBody = '';
      res.setEncoding('utf8');
      res.on('data', chunk => { responseBody += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, body: responseBody }));
    });

    req.setTimeout(timeout, () => {
      req.destroy();
      reject(new Error(`Webhook request timed out after ${timeout}ms`));
    });

    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

/**
 * Build a Slack-compatible message payload from an analysis result.
 * @param {import('../lib/analyzer').AnalysisResult} result
 * @returns {object}
 */
function _buildSlackPayload(result) {
  const { summary, threats, top_attacker_ips, file } = result;

  const riskEmoji = summary.risk_level === 'HIGH' ? ':red_circle:'
    : summary.risk_level === 'MEDIUM' ? ':large_yellow_circle:'
    : ':large_green_circle:';

  const topIps = top_attacker_ips.slice(0, 5)
    .map(a => `• \`${a.ip}\` — ${a.count} hits (${a.reason})`)
    .join('\n');

  return {
    text: `${riskEmoji} *guardlog Security Alert* — Risk: *${summary.risk_level}*`,
    attachments: [
      {
        color: summary.risk_level === 'HIGH' ? 'danger'
          : summary.risk_level === 'MEDIUM' ? 'warning' : 'good',
        fields: [
          { title: 'File', value: file, short: true },
          { title: 'Risk Level', value: summary.risk_level, short: true },
          { title: 'Total Requests', value: String(summary.total_requests), short: true },
          { title: 'Suspicious', value: String(summary.suspicious_requests), short: true },
          { title: 'Brute Force', value: String(threats.brute_force), short: true },
          { title: 'SQL Injection', value: String(threats.sql_injection), short: true },
          { title: 'XSS', value: String(threats.xss), short: true },
          { title: 'Bot Activity', value: String(threats.bot_activity), short: true },
          { title: 'Scan / 404 Flood', value: String(threats.scan_detection), short: true },
          ...(topIps ? [{ title: 'Top Attacker IPs', value: topIps, short: false }] : []),
        ],
        footer: `guardlog • ${result.timestamp}`,
      },
    ],
  };
}

module.exports = { send };
