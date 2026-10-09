/**
 * @fileoverview Scope Guard security control to enforce testing authorization boundaries.
 * Restricts target scanning to localhost and RFC 1918 private subnets unless explicitly overridden.
 */

/**
 * Checks whether an IPv4 string belongs to RFC 1918 or loopback ranges.
 *
 * @param {string} ip
 * @returns {boolean}
 */
export function isPrivateOrLocalIPv4(ip) {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) {
    return false;
  }

  const [a, b] = parts;

  // 127.0.0.0/8 (Loopback)
  if (a === 127) return true;

  // 10.0.0.0/8 (Private)
  if (a === 10) return true;

  // 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
  if (a === 172 && b >= 16 && b <= 31) return true;

  // 192.168.0.0/16 (Private)
  if (a === 192 && b === 168) return true;

  // 169.254.0.0/16 (Link-Local)
  if (a === 169 && b === 254) return true;

  // 0.0.0.0 (Current network)
  if (a === 0 && b === 0 && parts[2] === 0 && parts[3] === 0) return true;

  return false;
}

/**
 * Checks whether an IPv6 string belongs to loopback or local ranges.
 *
 * @param {string} ip
 * @returns {boolean}
 */
export function isPrivateOrLocalIPv6(ip) {
  const clean = ip.replace(/^\[|\]$/g, "").toLowerCase();
  if (clean === "::1" || clean === "0:0:0:0:0:0:0:1") return true;
  // Link-local: fe80::/10
  if (clean.startsWith("fe8") || clean.startsWith("fe9") || clean.startsWith("fea") || clean.startsWith("feb")) return true;
  // Unique local: fc00::/7 (fc00:: or fd00::)
  if (clean.startsWith("fc") || clean.startsWith("fd")) return true;
  return false;
}

/**
 * Validates target URL against scope authorization policies.
 *
 * @param {string} targetUrl - URL to be tested
 * @param {boolean} [iOwnThisTarget=false] - Explicit user authorization override flag
 * @returns {{ allowed: boolean, isLocal: boolean, warning?: string, error?: string }}
 */
export function validateTargetScope(targetUrl, iOwnThisTarget = false) {
  let parsed;
  try {
    parsed = new URL(targetUrl);
  } catch {
    return {
      allowed: false,
      isLocal: false,
      error: `Invalid URL format: "${targetUrl}". Expected format: http://localhost:3000 or https://target.local`
    };
  }

  const hostname = parsed.hostname.toLowerCase();

  const isLocalhost = hostname === "localhost" || hostname.endsWith(".localhost");
  const isPrivateIpv4 = isPrivateOrLocalIPv4(hostname);
  const isPrivateIpv6 = isPrivateOrLocalIPv6(hostname);

  const isLocal = isLocalhost || isPrivateIpv4 || isPrivateIpv6;

  if (isLocal) {
    return {
      allowed: true,
      isLocal: true
    };
  }

  // Target is external / public
  if (!iOwnThisTarget) {
    return {
      allowed: false,
      isLocal: false,
      error: `Scope Guard Protection: Target "${hostname}" appears to be an external/public host.\n` +
             `By default, api-sec-scanner only permits scans against localhost and private subnets.\n` +
             `To audit systems you own or are explicitly authorized to assess, supply the --i-own-this-target flag.`
    };
  }

  return {
    allowed: true,
    isLocal: false,
    warning: `WARNING: Authorizing scan against external host "${hostname}". Ensure you have explicit written authorization before scanning.`
  };
}
