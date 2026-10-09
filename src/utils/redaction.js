/**
 * @fileoverview Utility for redacting sensitive headers and credentials from request/response evidence.
 */

const SENSITIVE_HEADER_PATTERNS = [
  /^authorization$/i,
  /^proxy-authorization$/i,
  /^cookie$/i,
  /^set-cookie$/i,
  /^x-api-key$/i,
  /^api-key$/i,
  /^apikey$/i,
  /^token$/i,
  /^x-auth-token$/i,
  /^x-access-token$/i
];

/**
 * Checks whether a header name is considered sensitive.
 *
 * @param {string} headerName
 * @returns {boolean}
 */
export function isSensitiveHeader(headerName) {
  if (!headerName || typeof headerName !== "string") return false;
  return SENSITIVE_HEADER_PATTERNS.some((pattern) => pattern.test(headerName.trim()));
}

/**
 * Redacts sensitive values in a headers object or map.
 * Returns a new object with sensitive headers replaced by '[REDACTED]'.
 *
 * @param {Record<string, string> | Headers | undefined} headers
 * @returns {Record<string, string>}
 */
export function redactHeaders(headers) {
  if (!headers) return {};

  const cleanHeaders = {};

  if (typeof headers.entries === "function") {
    for (const [key, val] of headers.entries()) {
      cleanHeaders[key] = isSensitiveHeader(key) ? "[REDACTED]" : String(val);
    }
    return cleanHeaders;
  }

  for (const [key, val] of Object.entries(headers)) {
    cleanHeaders[key] = isSensitiveHeader(key) ? "[REDACTED]" : String(val);
  }

  return cleanHeaders;
}

/**
 * Truncates and redacts strings or JSON bodies for safe evidence display.
 *
 * @param {*} body
 * @param {number} [maxLength=1000]
 * @returns {string}
 */
export function sanitizeBodyExcerpt(body, maxLength = 1000) {
  if (body === undefined || body === null) return "";

  let text = typeof body === "string" ? body : JSON.stringify(body, null, 2);

  // Redact common token patterns if accidentally present in body
  text = text.replace(/("?(?:password|token|secret|apiKey|bearer)"?\s*[:=]\s*"?)[^",\s}]+("?)/gi, "$1[REDACTED]$2");

  if (text.length > maxLength) {
    return text.slice(0, maxLength) + "... [truncated]";
  }
  return text;
}
