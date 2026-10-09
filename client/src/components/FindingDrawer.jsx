import React from "react";
import { X, ShieldAlert, CheckCircle2 } from "lucide-react";
import SeverityBadge from "./SeverityBadge.jsx";
import CodeBlock from "./CodeBlock.jsx";

export default function FindingDrawer({ finding, onClose }) {
  if (!finding) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-hidden">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-sm transition-opacity"
        onClick={onClose}
      />

      <div className="fixed inset-y-0 right-0 max-w-2xl w-full flex pl-10">
        <div className="w-full bg-[#0d121d] border-l border-slate-800 p-6 overflow-y-auto shadow-2xl flex flex-col justify-between">
          <div>
            {/* Header */}
            <div className="flex items-start justify-between pb-4 border-b border-slate-800">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={finding.severity} />
                  <span className="font-mono text-xs text-slate-400">{finding.id}</span>
                  <span className="bg-slate-800 text-slate-300 font-mono text-xs px-2 py-0.5 rounded font-bold">
                    CVSS {finding.cvssScore ? finding.cvssScore.toFixed(1) : "0.0"}
                  </span>
                </div>
                <h2 className="text-lg font-bold text-slate-100">{finding.title}</h2>
              </div>
              <button
                onClick={onClose}
                className="p-1 rounded-md text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
                title="Close drawer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Target info */}
            <div className="my-4 p-3 rounded-lg bg-[#070a12] border border-slate-800/80 flex items-center justify-between font-mono text-xs">
              <div className="flex items-center gap-2">
                <span className="font-bold px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                  {finding.method}
                </span>
                <span className="text-slate-300">{finding.endpoint}</span>
              </div>
            </div>

            {/* Description */}
            <div className="my-4">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">
                Vulnerability Overview
              </h3>
              <p className="text-sm text-slate-300 leading-relaxed bg-[#111726]/50 p-3 rounded-lg border border-slate-800/60">
                {finding.description}
              </p>
            </div>

            {/* Evidence */}
            <div className="my-5">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2 flex items-center gap-1.5">
                <ShieldAlert className="w-4 h-4 text-amber-400" />
                Technical Evidence
              </h3>

              {finding.evidence?.requestSent && (
                <CodeBlock
                  title="Request Dispatched (Redacted)"
                  code={finding.evidence.requestSent}
                  language="json"
                />
              )}

              {finding.evidence?.responseReceived && (
                <div className="mt-3">
                  <div className="text-xs font-medium text-slate-400 mb-1">
                    Response Status: <span className="font-mono text-slate-200 font-bold">{finding.evidence.responseReceived.status}</span>
                  </div>
                  <CodeBlock
                    title="Response Received (Redacted)"
                    code={finding.evidence.responseReceived}
                    language="json"
                  />
                </div>
              )}
            </div>

            {/* Remediation */}
            <div className="my-5">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2 flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                Remediation & Hardening Guidance
              </h3>
              <p className="text-sm text-slate-300 leading-relaxed mb-2">
                {finding.remediation?.explanation || "Apply defense-in-depth principles and standard security headers."}
              </p>
              {finding.remediation?.codeSnippet && (
                <CodeBlock
                  title="Recommended Code Fix"
                  code={finding.remediation.codeSnippet}
                  language="javascript"
                />
              )}
            </div>
          </div>

          {/* Drawer footer */}
          <div className="pt-4 border-t border-slate-800 flex justify-end">
            <button
              onClick={onClose}
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg transition-colors"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
