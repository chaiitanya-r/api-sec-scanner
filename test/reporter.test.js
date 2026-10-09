import { describe, it, expect } from "vitest";
import fs from "node:fs/promises";
import path from "node:path";
import { buildScanReport, writeJsonReport } from "../src/reporter/jsonReporter.js";
import { generateHtmlReport, writeHtmlReport, escapeHtml } from "../src/reporter/htmlReporter.js";

describe("Reporters (JSON and HTML)", () => {
  const dummyFindings = [
    {
      id: "RATE-LIMIT-001",
      title: "Missing Rate Limiting",
      severity: "MEDIUM",
      cvssScore: 5.5,
      endpoint: "/api/burst",
      method: "POST",
      description: "No rate limit found.",
      evidence: { requestSent: { method: "POST", url: "/api/burst", headers: {} }, responseReceived: { status: 200, headers: {}, bodyExcerpt: "ok" } },
      remediation: { explanation: "Use limiter", codeSnippet: "app.use(limiter)" }
    },
    {
      id: "AUTH-001",
      title: "Missing Auth",
      severity: "HIGH",
      cvssScore: 7.5,
      endpoint: "/api/private",
      method: "GET",
      description: "Auth missing.",
      evidence: { requestSent: { method: "GET", url: "/api/private", headers: {} }, responseReceived: { status: 200, headers: {}, bodyExcerpt: "leak" } },
      remediation: { explanation: "Add auth", codeSnippet: "app.use(auth)" }
    }
  ];

  describe("JSON Reporter", () => {
    it("should build structured report with correct counts and sorting", () => {
      const report = buildScanReport({
        target: "http://localhost:3000",
        specPath: "./openapi.yaml",
        durationMs: 120,
        findings: dummyFindings
      });

      expect(report.scanner).toBe("api-sec-scanner");
      expect(report.summary.total).toBe(2);
      expect(report.summary.high).toBe(1);
      expect(report.summary.medium).toBe(1);
      expect(report.summary.critical).toBe(0);

      // Verify deterministic sorting: HIGH before MEDIUM
      expect(report.findings[0].severity).toBe("HIGH");
      expect(report.findings[1].severity).toBe("MEDIUM");
    });

    it("should write valid JSON file to disk", async () => {
      const report = buildScanReport({
        target: "http://localhost:3000",
        specPath: "./openapi.yaml",
        durationMs: 50,
        findings: dummyFindings
      });

      const tempPath = path.resolve(__dirname, "temp-report.json");
      await writeJsonReport(tempPath, report);

      const content = await fs.readFile(tempPath, "utf-8");
      const parsed = JSON.parse(content);
      expect(parsed.target).toBe("http://localhost:3000");
      expect(parsed.findings.length).toBe(2);

      await fs.unlink(tempPath);
    });
  });

  describe("HTML Reporter", () => {
    it("escapeHtml should safely escape HTML entities", () => {
      expect(escapeHtml("<script>alert('xss')</script>")).toBe(
        "&lt;script&gt;alert(&#039;xss&#039;)&lt;/script&gt;"
      );
    });

    it("should generate valid standalone HTML with styled components", () => {
      const report = buildScanReport({
        target: "http://localhost:3000",
        specPath: "./openapi.yaml",
        durationMs: 50,
        findings: dummyFindings
      });

      const html = generateHtmlReport(report);
      expect(html).toContain("<!DOCTYPE html>");
      expect(html).toContain("api-sec-scanner Audit Report");
      expect(html).toContain("Missing Auth");
      expect(html).toContain("Missing Rate Limiting");
      expect(html).toContain("CVSS 7.5");
    });

    it("should write valid HTML file to disk", async () => {
      const report = buildScanReport({
        target: "http://localhost:3000",
        specPath: "./openapi.yaml",
        durationMs: 50,
        findings: dummyFindings
      });

      const tempPath = path.resolve(__dirname, "temp-report.html");
      await writeHtmlReport(tempPath, report);

      const content = await fs.readFile(tempPath, "utf-8");
      expect(content).toContain("<html");
      expect(content).toContain("</html>");

      await fs.unlink(tempPath);
    });
  });
});
