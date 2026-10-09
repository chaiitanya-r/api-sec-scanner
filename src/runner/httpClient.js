import { fetch } from "undici";
import pLimit from "p-limit";
import { redactHeaders, sanitizeBodyExcerpt } from "../utils/redaction.js";

/**
 * Creates a configured HTTP client with rate limiting, timeouts, retries,
 * and automatic redaction of sensitive credentials in telemetry.
 *
 * @param {Object} [options]
 * @param {string} [options.baseUrl='http://localhost:3000']
 * @param {number} [options.timeoutMs=5000]
 * @param {number} [options.retries=1]
 * @param {number} [options.concurrency=5]
 */
export function createHttpClient(options = {}) {
  const {
    baseUrl = "http://localhost:3000",
    timeoutMs = 5000,
    retries = 1,
    concurrency = 5
  } = options;

  const limit = pLimit(Math.max(1, concurrency));
  const normalizedBaseUrl = baseUrl.replace(/\/+$/, "");

  /**
   * Sends an HTTP request with bounded retries and timeout.
   *
   * @param {Object} reqOptions
   * @param {string} reqOptions.method - HTTP method (GET, POST, etc.)
   * @param {string} reqOptions.path - Endpoint path or query string
   * @param {Record<string, string>} [reqOptions.headers] - Request headers
   * @param {string|Object} [reqOptions.body] - Request body
   * @returns {Promise<Object>} Formatted request/response metadata
   */
  async function sendRequest(reqOptions) {
    const { method = "GET", path = "/", headers = {}, body } = reqOptions;
    const url = path.startsWith("http://") || path.startsWith("https://")
      ? path
      : `${normalizedBaseUrl}${path.startsWith("/") ? "" : "/"}${path}`;

    const safeRequestSent = {
      method: method.toUpperCase(),
      url,
      headers: redactHeaders(headers),
      ...(body ? { bodyExcerpt: sanitizeBodyExcerpt(body) } : {})
    };

    let serializedBody;
    const requestHeaders = { ...headers };
    if (body !== undefined && body !== null) {
      if (typeof body === "object" && !(body instanceof Uint8Array)) {
        serializedBody = JSON.stringify(body);
        if (!requestHeaders["content-type"] && !requestHeaders["Content-Type"]) {
          requestHeaders["Content-Type"] = "application/json";
        }
      } else {
        serializedBody = String(body);
      }
    }

    return limit(async () => {
      let attempts = 0;
      const maxAttempts = Math.min(3, Math.max(1, 1 + retries));
      let lastError = null;

      while (attempts < maxAttempts) {
        attempts++;
        const startTime = Date.now();

        try {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), timeoutMs);

          const res = await fetch(url, {
            method: method.toUpperCase(),
            headers: requestHeaders,
            body: ["GET", "HEAD"].includes(method.toUpperCase()) ? undefined : serializedBody,
            signal: controller.signal
          });

          clearTimeout(timer);
          const durationMs = Date.now() - startTime;

          const resHeaders = {};
          res.headers.forEach((value, key) => {
            resHeaders[key.toLowerCase()] = value;
          });

          const rawText = await res.text();

          return {
            ok: res.ok,
            status: res.status,
            statusText: res.statusText,
            headers: resHeaders,
            durationMs,
            bodyText: rawText,
            evidence: {
              requestSent: safeRequestSent,
              responseReceived: {
                status: res.status,
                headers: redactHeaders(resHeaders),
                bodyExcerpt: sanitizeBodyExcerpt(rawText)
              }
            }
          };
        } catch (err) {
          lastError = err;
          // Only retry on network errors, not abort or when attempts reached
          if (attempts >= maxAttempts) {
            break;
          }
          // Short delay before retry
          await new Promise((r) => setTimeout(r, 100));
        }
      }

      // Safe fallback on network/timeout failure
      return {
        ok: false,
        status: 0,
        statusText: "NETWORK_ERROR",
        headers: {},
        durationMs: 0,
        bodyText: "",
        error: lastError ? lastError.message : "Request failed",
        evidence: {
          requestSent: safeRequestSent,
          responseReceived: {
            status: 0,
            headers: {},
            bodyExcerpt: `Network/connection error: ${lastError ? lastError.message : "Unknown error"}`
          }
        }
      };
    });
  }

  return {
    sendRequest,
    baseUrl: normalizedBaseUrl
  };
}
