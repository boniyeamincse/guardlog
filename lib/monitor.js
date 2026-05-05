'use strict';

/**
 * Live Monitor
 *
 * Watches a log file for new lines (tail -f equivalent) and runs
 * the analysis on each incoming batch of entries.
 */

const fs = require('fs');
const readline = require('readline');
const { parseLine } = require('./parser');
const { analyzeEntries } = require('./analyzer');

const BATCH_FLUSH_MS = 5_000;  // analyze accumulated entries every 5s
const MAX_BATCH_SIZE = 500;    // or when batch reaches this size

/**
 * @param {string} filePath
 * @param {{ onResult: (result: import('./analyzer').AnalysisResult) => void, signal?: AbortSignal }} opts
 */
function monitor(filePath, opts) {
  const { onResult, signal } = opts;

  // Seek to end of file first so we only see new lines
  const stat = fs.statSync(filePath);
  let position = stat.size;

  /** @type {import('./parser').ParsedEntry[]} */
  let batch = [];
  let flushTimer = null;

  const flushBatch = () => {
    if (batch.length === 0) return;
    const toAnalyze = batch.splice(0);
    const result = analyzeEntries(toAnalyze, filePath);
    onResult(result);
  };

  const processChunk = (chunk) => {
    const lines = chunk.split('\n');
    for (const line of lines) {
      const entry = parseLine(line.trim());
      if (entry) {
        batch.push(entry);
        if (batch.length >= MAX_BATCH_SIZE) {
          clearTimeout(flushTimer);
          flushBatch();
          flushTimer = setTimeout(flushBatch, BATCH_FLUSH_MS);
        }
      }
    }
  };

  // Use fs.watch to detect file changes, then read new bytes
  const watcher = fs.watch(filePath, (eventType) => {
    if (eventType !== 'change') return;
    if (signal?.aborted) {
      watcher.close();
      return;
    }

    const newStat = fs.statSync(filePath);
    if (newStat.size <= position) return;  // truncated or no new data

    const stream = fs.createReadStream(filePath, {
      encoding: 'utf8',
      start: position,
      end: newStat.size - 1,
    });

    let buffer = '';
    stream.on('data', chunk => { buffer += chunk; });
    stream.on('end', () => {
      position = newStat.size;
      processChunk(buffer);

      clearTimeout(flushTimer);
      flushTimer = setTimeout(flushBatch, BATCH_FLUSH_MS);
    });
  });

  if (signal) {
    signal.addEventListener('abort', () => {
      watcher.close();
      clearTimeout(flushTimer);
      flushBatch();
    }, { once: true });
  }

  return watcher;
}

module.exports = { monitor };
