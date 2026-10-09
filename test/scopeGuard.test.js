import { describe, it, expect } from "vitest";
import { validateTargetScope, isPrivateOrLocalIPv4, isPrivateOrLocalIPv6 } from "../src/safety/scopeGuard.js";

describe("Scope Guard Target Authorization", () => {
  describe("IPv4 & IPv6 Evaluation", () => {
    it("should recognize private and loopback IPv4 ranges", () => {
      expect(isPrivateOrLocalIPv4("127.0.0.1")).toBe(true);
      expect(isPrivateOrLocalIPv4("10.10.1.5")).toBe(true);
      expect(isPrivateOrLocalIPv4("172.16.0.1")).toBe(true);
      expect(isPrivateOrLocalIPv4("172.31.255.255")).toBe(true);
      expect(isPrivateOrLocalIPv4("192.168.1.100")).toBe(true);
      expect(isPrivateOrLocalIPv4("169.254.1.1")).toBe(true);

      // Public IPs
      expect(isPrivateOrLocalIPv4("8.8.8.8")).toBe(false);
      expect(isPrivateOrLocalIPv4("93.184.216.34")).toBe(false);
      expect(isPrivateOrLocalIPv4("172.32.0.1")).toBe(false);
    });

    it("should recognize private and loopback IPv6 addresses", () => {
      expect(isPrivateOrLocalIPv6("::1")).toBe(true);
      expect(isPrivateOrLocalIPv6("fe80::1")).toBe(true);
      expect(isPrivateOrLocalIPv6("fc00::1")).toBe(true);
      expect(isPrivateOrLocalIPv6("2001:4860:4860::8888")).toBe(false);
    });
  });

  describe("validateTargetScope", () => {
    it("should permit localhost targets automatically", () => {
      const res = validateTargetScope("http://localhost:3000");
      expect(res.allowed).toBe(true);
      expect(res.isLocal).toBe(true);
    });

    it("should permit 127.0.0.1 targets automatically", () => {
      const res = validateTargetScope("http://127.0.0.1:8080");
      expect(res.allowed).toBe(true);
      expect(res.isLocal).toBe(true);
    });

    it("should permit private RFC 1918 subnets automatically", () => {
      const res = validateTargetScope("http://192.168.1.50:4000");
      expect(res.allowed).toBe(true);
      expect(res.isLocal).toBe(true);
    });

    it("should REJECT external targets without ownership flag", () => {
      const res = validateTargetScope("https://api.external-target.com");
      expect(res.allowed).toBe(false);
      expect(res.isLocal).toBe(false);
      expect(res.error).toContain("Scope Guard Protection");
    });

    it("should ALLOW external targets when explicit ownership flag is passed", () => {
      const res = validateTargetScope("https://api.external-target.com", true);
      expect(res.allowed).toBe(true);
      expect(res.isLocal).toBe(false);
      expect(res.warning).toContain("WARNING: Authorizing scan against external host");
    });

    it("should reject malformed URLs", () => {
      const res = validateTargetScope("not-a-valid-url");
      expect(res.allowed).toBe(false);
      expect(res.error).toContain("Invalid URL format");
    });
  });
});
