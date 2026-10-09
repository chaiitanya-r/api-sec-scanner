/**
 * @fileoverview CVSS-style score mapping for api-sec-scanner findings.
 * Note: These are internal CVSS-style scores for vulnerability prioritization,
 * not formal CVSS v3.1/v4.0 vector metrics calculations.
 */

export const SEVERITY_SCORES = {
  CRITICAL: 9.5,
  HIGH: 7.5,
  MEDIUM: 5.5,
  LOW: 3.0,
  INFO: 0.0
};

/**
 * Returns a deterministic CVSS-style score for a given severity.
 *
 * @param {string} severity - 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
 * @returns {number}
 */
export function getCvssScore(severity) {
  const normalized = (severity || "").toUpperCase();
  return SEVERITY_SCORES[normalized] !== undefined ? SEVERITY_SCORES[normalized] : 0.0;
}
