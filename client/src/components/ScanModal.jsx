import React, { useState } from "react";
import { X, Play, ShieldAlert, CheckCircle2, AlertTriangle, Loader2 } from "lucide-react";

export default function ScanModal({ isOpen, onClose, onScanComplete }) {
  const [baseUrl, setBaseUrl] = useState("http://127.0.0.1:3000");
  const [specPath, setSpecPath] = useState("./testbed/openapi.yaml");
  const [burst, setBurst] = useState(30);
  const [checks, setChecks] = useState({
    headers: true,
    cors: true,
    auth: true,
    rate: true
  });
  const [iOwnThisTarget, setIOwnThisTarget] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  if (!isOpen) return null;

  const handleCheckboxChange = (name) => {
    setChecks((prev) => ({ ...prev, [name]: !prev[name] }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    const activeChecks = Object.keys(checks)
      .filter((k) => checks[k])
      .join(",");

    if (!activeChecks) {
      setError("Please select at least one security check.");
      setLoading(false);
      return;
    }

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          baseUrl,
          specPath,
          checks: activeChecks,
          burst: parseInt(burst, 10) || 30,
          iOwnThisTarget
        })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.details || data.error || "Scan failed to execute");
      }

      if (data.report) {
        onScanComplete(data.report);
        onClose();
      }
    } catch (err) {
      setError(
        err.message.includes("Failed to fetch")
          ? "Cannot connect to scanner server. Start it with 'npm run dashboard' or 'node src/server.js'."
          : err.message
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto flex items-center justify-center p-4">
      <div className="fixed inset-0 bg-black/70 backdrop-blur-sm transition-opacity" onClick={onClose} />

      <div className="relative bg-[#0d121e] border border-slate-800 rounded-xl max-w-lg w-full p-6 shadow-2xl text-slate-100 z-10">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-cyan-600/20 text-cyan-400 flex items-center justify-center border border-cyan-500/30">
              <Play className="w-4 h-4 fill-current" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white">Run Security Audit</h2>
              <p className="text-xs text-slate-400">Launch an automated DAST scan against target API</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-md text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {error && (
          <div className="mt-4 p-3 bg-red-950/40 border border-red-800/80 rounded-lg text-xs text-red-300 flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="mt-4 space-y-4 text-xs">
          <div>
            <label className="block font-medium text-slate-300 mb-1">Target Base URL</label>
            <input
              type="text"
              required
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
              placeholder="http://127.0.0.1:3000"
              className="w-full bg-[#121826] border border-slate-700 rounded-lg px-3 py-2 text-slate-100 font-mono focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div>
            <label className="block font-medium text-slate-300 mb-1">OpenAPI Specification Path</label>
            <input
              type="text"
              required
              value={specPath}
              onChange={(e) => setSpecPath(e.target.value)}
              placeholder="./testbed/openapi.yaml"
              className="w-full bg-[#121826] border border-slate-700 rounded-lg px-3 py-2 text-slate-100 font-mono focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div>
            <label className="block font-medium text-slate-300 mb-1.5">Enabled Defensive Checks</label>
            <div className="grid grid-cols-2 gap-2">
              {[
                { id: "headers", label: "Security Headers" },
                { id: "cors", label: "CORS Misconfigurations" },
                { id: "auth", label: "Auth Enforcement" },
                { id: "rate", label: "Rate Limiting Burst" }
              ].map((c) => (
                <label
                  key={c.id}
                  className={`flex items-center gap-2 p-2 rounded-lg border cursor-pointer transition-colors ${
                    checks[c.id]
                      ? "bg-cyan-950/40 border-cyan-700/60 text-cyan-200"
                      : "bg-[#121826] border-slate-800 text-slate-400"
                  }`}
                >
                  <input
                    type="checkbox"
                    checked={checks[c.id]}
                    onChange={() => handleCheckboxChange(c.id)}
                    className="accent-cyan-500"
                  />
                  <span className="font-medium text-xs">{c.label}</span>
                </label>
              ))}
            </div>
          </div>

          <div>
            <div className="flex justify-between items-center mb-1">
              <label className="font-medium text-slate-300">Rate Limit Burst Probe Count</label>
              <span className="font-mono text-cyan-400">{burst} reqs</span>
            </div>
            <input
              type="range"
              min="5"
              max="100"
              value={burst}
              onChange={(e) => setBurst(e.target.value)}
              className="w-full accent-cyan-500 cursor-pointer"
            />
          </div>

          <div className="pt-2 border-t border-slate-800">
            <label className="flex items-start gap-2 cursor-pointer text-slate-300">
              <input
                type="checkbox"
                checked={iOwnThisTarget}
                onChange={(e) => setIOwnThisTarget(e.target.checked)}
                className="accent-cyan-500 mt-0.5"
              />
              <span className="text-[11px] leading-tight text-slate-400">
                I authorize security audits against this target (<code className="text-cyan-400">--i-own-this-target</code> scope authorization required for non-localhost/private IP targets).
              </span>
            </label>
          </div>

          <div className="flex items-center justify-end gap-3 pt-3">
            <button
              type="button"
              onClick={onClose}
              disabled={loading}
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 rounded-lg text-slate-300 font-medium transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="px-4 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 rounded-lg text-white font-semibold flex items-center gap-2 shadow-lg shadow-cyan-600/20 transition-all disabled:opacity-50"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Scanning Target...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current" />
                  <span>Execute Audit</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
