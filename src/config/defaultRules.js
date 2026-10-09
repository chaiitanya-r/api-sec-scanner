/**
 * @fileoverview Default operational parameters and security check configuration.
 */

export const defaultRules = {
  checks: {
    headers: true,
    cors: true,
    auth: true,
    rate: true
  },
  network: {
    timeoutMs: 5000,
    retries: 1,
    concurrency: 5
  },
  rateLimit: {
    burst: 30,
    maxBurst: 100
  },
  severityOrder: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
};
