/**
 * @fileoverview JSDoc type definitions for security findings and scan reports.
 */

/**
 * @typedef {'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'} SeverityLevel
 */

/**
 * @typedef {Object} FindingEvidence
 * @property {Object} requestSent
 * @property {string} requestSent.method
 * @property {string} requestSent.url
 * @property {Record<string, string>} requestSent.headers
 * @property {string} [requestSent.bodyExcerpt]
 * @property {Object} responseReceived
 * @property {number} responseReceived.status
 * @property {Record<string, string>} responseReceived.headers
 * @property {string} responseReceived.bodyExcerpt
 */

/**
 * @typedef {Object} FindingRemediation
 * @property {string} explanation
 * @property {string} codeSnippet
 */

/**
 * @typedef {Object} AuditFinding
 * @property {string} id - Finding identifier (e.g. 'SEC-HDR-001')
 * @property {string} title - Short descriptive finding title
 * @property {SeverityLevel} severity - Finding severity
 * @property {number} cvssScore - CVSS-style internal score (0.0 - 10.0)
 * @property {string} endpoint - API path template (e.g. '/api/users/{id}')
 * @property {string} method - HTTP method
 * @property {string} description - Detailed explanation of the issue
 * @property {FindingEvidence} evidence - Redacted request and response details
 * @property {FindingRemediation} remediation - Guidance and remediation code snippet
 */

/**
 * @typedef {Object} ScanSummary
 * @property {number} critical
 * @property {number} high
 * @property {number} medium
 * @property {number} low
 * @property {number} info
 * @property {number} total
 */

/**
 * @typedef {Object} ScanReport
 * @property {string} scanner - 'api-sec-scanner'
 * @property {string} version - Scanner version
 * @property {string} timestamp - ISO timestamp of scan
 * @property {string} target - Base URL of target API
 * @property {string} specPath - Path to OpenAPI spec
 * @property {number} durationMs - Scan duration in milliseconds
 * @property {ScanSummary} summary - Aggregated severity counts
 * @property {AuditFinding[]} findings - Deterministically sorted list of findings
 */

export {};
