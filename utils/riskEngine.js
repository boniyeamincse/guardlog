'use strict';

/**
 * Risk Engine
 *
 * Assigns a risk level (LOW / MEDIUM / HIGH) based on the scan results.
 */

/**
 * @param {Object} threats
 * @param {number} threats.bruteForce
 * @param {number} threats.sqlInjection
 * @param {number} threats.xss
 * @param {number} threats.botActivity
 * @param {number} totalRequests
 * @returns {'LOW'|'MEDIUM'|'HIGH'}
 */
function calculateRisk(threats, totalRequests) {
  const totalSuspicious = threats.bruteForce + threats.sqlInjection + threats.xss + threats.botActivity;

  // Any direct injection/execution attack = immediate HIGH
  if (threats.sqlInjection > 0 || threats.xss > 0) return 'HIGH';
  if (threats.bruteForce > 5) return 'HIGH';

  // Significant bot activity or moderate brute force
  if (threats.botActivity > 50) return 'HIGH';
  if (threats.bruteForce > 0 || threats.botActivity > 10) return 'MEDIUM';

  // Percentage-based check: >5% suspicious = MEDIUM
  if (totalRequests > 0 && (totalSuspicious / totalRequests) > 0.05) return 'MEDIUM';

  return 'LOW';
}

/**
 * Score value for exit code and sorting purposes.
 * @param {'LOW'|'MEDIUM'|'HIGH'} level
 * @returns {number}
 */
function riskScore(level) {
  return { LOW: 0, MEDIUM: 1, HIGH: 2 }[level] ?? 0;
}

module.exports = { calculateRisk, riskScore };
