import React, { useState, useEffect } from "react";
import {
  Shield,
  Upload,
  FileText,
  Globe,
  Clock,
  Moon,
  Sun,
  RefreshCw,
  Play,
  Download,
  Printer,
  CheckCircle,
  Activity
} from "lucide-react";
import SummaryCards from "./components/SummaryCards.jsx";
import FindingsTable from "./components/FindingsTable.jsx";
import FindingDrawer from "./components/FindingDrawer.jsx";
import ScanModal from "./components/ScanModal.jsx";

const DEFAULT_DEMO_REPORT = {
  scanner: "api-sec-scanner",
  version: "1.0.0",
  timestamp: new Date().toISOString(),
  target: "http://localhost:3000",
  specPath: "./openapi.yaml",
  durationMs: 420,
  summary: {
    critical: 0,
    high: 2,
    medium: 3,
    low: 4,
    info: 0,
    total: 9
  },
  findings: [
    {
      id: "AUTH-001",
      title: "Protected endpoint does not enforce authentication",
      severity: "HIGH",
      cvssScore: 7.5,
      endpoint: "/api/private-profile",
      method: "GET",
      description: "The OpenAPI specification marks this endpoint as requiring authentication, but a request without credentials returned HTTP 200 instead of 401 or 403.",
      evidence: {
        requestSent: {
          method: "GET",
          url: "http://localhost:3000/api/private-profile",
          headers: {}
        },
        responseReceived: {
          status: 200,
          headers: { "content-type": "application/json" },
          bodyExcerpt: '{"id":42,"username":"alice_admin","role":"administrator"}'
        }
      },
      remediation: {
        explanation: "Mount authentication middleware on the endpoint to reject requests without a valid session or Bearer token.",
        codeSnippet: 'import { requireAuth } from "./middleware/auth.js";\n\napp.use("/api/private-profile", requireAuth);'
      }
    },
    {
      id: "CORS-WILD-001",
      title: "Wildcard CORS Access-Control-Allow-Origin: *",
      severity: "MEDIUM",
      cvssScore: 5.5,
      endpoint: "/api/public-data",
      method: "GET",
      description: "The API sets 'Access-Control-Allow-Origin: *', allowing any arbitrary domain to access this resource.",
      evidence: {
        requestSent: {
          method: "GET",
          url: "http://localhost:3000/api/public-data",
          headers: { origin: "https://audit-probe.example.com" }
        },
        responseReceived: {
          status: 200,
          headers: { "access-control-allow-origin": "*" },
          bodyExcerpt: '{"items":["item1","item2"]}'
        }
      },
      remediation: {
        explanation: "Specify an explicit list of trusted origins using the cors middleware.",
        codeSnippet: 'import cors from "cors";\n\napp.use(cors({\n  origin: ["https://app.example.com"]\n}));'
      }
    },
    {
      id: "RATE-LIMIT-001",
      title: "Missing Rate Limiting Enforcement",
      severity: "MEDIUM",
      cvssScore: 5.5,
      endpoint: "/api/action-burst",
      method: "POST",
      description: "The endpoint did not throttle or return HTTP 429 after a controlled burst of 30 requests.",
      evidence: {
        requestSent: {
          method: "POST",
          url: "http://localhost:3000/api/action-burst",
          headers: {}
        },
        responseReceived: {
          status: 200,
          headers: {},
          bodyExcerpt: '{"success":true,"action":"burst_processed"}'
        }
      },
      remediation: {
        explanation: "Apply express-rate-limit to protect the endpoint from automated request bursts.",
        codeSnippet: 'import rateLimit from "express-rate-limit";\n\nconst limiter = rateLimit({\n  windowMs: 15 * 60 * 1000,\n  max: 100\n});\n\napp.use("/api/action-burst", limiter);'
      }
    },
    {
      id: "INFO-LEAK-001",
      title: "Server Technology Leakage via X-Powered-By",
      severity: "LOW",
      cvssScore: 3.0,
      endpoint: "/api/private-profile",
      method: "GET",
      description: "The server exposes its underlying framework in the X-Powered-By header.",
      evidence: {
        requestSent: {
          method: "GET",
          url: "http://localhost:3000/api/private-profile",
          headers: {}
        },
        responseReceived: {
          status: 200,
          headers: { "x-powered-by": "Express/4.21.0-Vulnerable" },
          bodyExcerpt: "{...}"
        }
      },
      remediation: {
        explanation: "Disable the X-Powered-By header in Express or use Helmet.",
        codeSnippet: 'app.disable("x-powered-by");\n// Or with helmet:\napp.use(helmet.hidePoweredBy());'
      }
    }
  ]
};

export default function App() {
  const [report, setReport] = useState(DEFAULT_DEMO_REPORT);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [severityFilter, setSeverityFilter] = useState(null);
  const [isDarkMode, setIsDarkMode] = useState(true);
  const [isScanModalOpen, setIsScanModalOpen] = useState(false);
  const [serverActive, setServerActive] = useState(false);

  // Check backend server status
  useEffect(() => {
    fetch("/api/health")
      .then((res) => {
        if (res.ok) setServerActive(true);
      })
      .catch(() => {
        setServerActive(false);
      });
  }, []);

  // Attempt to load report from server or public folder
  useEffect(() => {
    fetch("/api/report")
      .then((res) => {
        if (res.ok) return res.json();
        return fetch("/report.json").then((r) => (r.ok ? r.json() : null));
      })
      .then((data) => {
        if (data && data.findings) {
          setReport(data);
        }
      })
      .catch(() => {
        // Keep default demonstration report
      });
  }, []);

  const handleFileUpload = (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const parsed = JSON.parse(event.target.result);
        if (parsed.findings) {
          setReport(parsed);
          setSelectedFinding(null);
          setSeverityFilter(null);
        } else {
          alert("Invalid report format: Missing 'findings' array.");
        }
      } catch {
        alert("Failed to parse report file. Ensure it is valid JSON.");
      }
    };
    reader.readAsText(file);
  };

  const handleDownloadJson = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(report, null, 2));
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `api-sec-report-${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className={`min-h-screen ${isDarkMode ? "bg-[#090d15] text-slate-100" : "bg-slate-50 text-slate-900"}`}>
      {/* Top Navbar */}
      <header className="border-b border-slate-800/80 bg-[#0c101a]/90 backdrop-blur sticky top-0 z-30">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-gradient-to-tr from-cyan-600 to-blue-500 flex items-center justify-center shadow-lg shadow-cyan-500/20">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-base tracking-tight text-white">api-sec-scanner</span>
                <span className="text-[10px] font-mono font-semibold bg-cyan-950 text-cyan-300 border border-cyan-800 px-1.5 py-0.5 rounded">
                  v{report.version || "1.0.0"}
                </span>
                <span
                  className={`text-[10px] font-medium px-2 py-0.5 rounded-full flex items-center gap-1 border ${
                    serverActive
                      ? "bg-emerald-950/60 text-emerald-400 border-emerald-800/60"
                      : "bg-slate-800 text-slate-400 border-slate-700"
                  }`}
                  title={serverActive ? "Connected to backend server" : "Running in client-only demo mode"}
                >
                  <span className={`w-1.5 h-1.5 rounded-full ${serverActive ? "bg-emerald-400 animate-pulse" : "bg-slate-500"}`} />
                  {serverActive ? "API Ready" : "Demo Mode"}
                </span>
              </div>
              <p className="text-[11px] text-slate-400">Automated API Security Scanner &amp; DAST Engine</p>
            </div>
          </div>

          <div className="flex items-center gap-2 sm:gap-3">
            {/* New Scan Button */}
            <button
              onClick={() => setIsScanModalOpen(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-semibold rounded-lg shadow-md shadow-cyan-600/20 transition-all"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>Audit Target</span>
            </button>

            {/* Upload report.json */}
            <label className="hidden sm:flex items-center gap-1.5 px-3 py-1.5 bg-slate-800/90 hover:bg-slate-700 text-slate-200 text-xs font-medium rounded-lg cursor-pointer transition-colors border border-slate-700">
              <Upload className="w-3.5 h-3.5 text-cyan-400" />
              <span>Load JSON</span>
              <input type="file" accept=".json" onChange={handleFileUpload} className="hidden" />
            </label>

            {/* Download JSON */}
            <button
              onClick={handleDownloadJson}
              className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition-colors"
              title="Download JSON Report"
            >
              <Download className="w-4 h-4" />
            </button>

            {/* Print / Save */}
            <button
              onClick={handlePrint}
              className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition-colors"
              title="Print Summary / Save PDF"
            >
              <Printer className="w-4 h-4" />
            </button>

            {/* Reset to demo */}
            <button
              onClick={() => {
                setReport(DEFAULT_DEMO_REPORT);
                setSelectedFinding(null);
                setSeverityFilter(null);
              }}
              className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition-colors"
              title="Reset to demo data"
            >
              <RefreshCw className="w-4 h-4" />
            </button>

            {/* Dark mode toggle */}
            <button
              onClick={() => setIsDarkMode(!isDarkMode)}
              className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition-colors"
              title="Toggle theme"
            >
              {isDarkMode ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
            </button>
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Metadata Banner */}
        <div className="bg-[#101522] border border-slate-800/80 rounded-xl p-4 mb-6 flex flex-wrap items-center justify-between gap-4 text-xs">
          <div className="flex items-center gap-6 flex-wrap">
            <div className="flex items-center gap-2">
              <Globe className="w-4 h-4 text-cyan-400" />
              <span className="text-slate-400">Target:</span>
              <span className="font-mono font-medium text-slate-200">{report.target}</span>
            </div>
            <div className="flex items-center gap-2">
              <FileText className="w-4 h-4 text-slate-400" />
              <span className="text-slate-400">Spec:</span>
              <span className="font-mono text-slate-300">{report.specPath}</span>
            </div>
            <div className="flex items-center gap-2">
              <Clock className="w-4 h-4 text-slate-400" />
              <span className="text-slate-400">Duration:</span>
              <span className="font-mono text-slate-300">{report.durationMs}ms</span>
            </div>
          </div>
          <div className="text-slate-400 font-mono text-[11px] flex items-center gap-2">
            <span>Scan Time:</span>
            <span className="text-slate-300">
              {report.timestamp ? new Date(report.timestamp).toLocaleString() : "N/A"}
            </span>
          </div>
        </div>

        {/* Severity Count Summary Cards */}
        <SummaryCards
          summary={report.summary}
          activeFilter={severityFilter}
          onSelectFilter={(sev) => setSeverityFilter(sev)}
        />

        {/* Findings Table */}
        <FindingsTable
          findings={report.findings || []}
          selectedFinding={selectedFinding}
          onSelectFinding={(f) => setSelectedFinding(f)}
          severityFilter={severityFilter}
          onClearFilter={() => setSeverityFilter(null)}
        />
      </main>

      {/* Slide-out Drawer */}
      <FindingDrawer
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
      />

      {/* New Scan Modal */}
      <ScanModal
        isOpen={isScanModalOpen}
        onClose={() => setIsScanModalOpen(false)}
        onScanComplete={(newReport) => {
          setReport(newReport);
          setSelectedFinding(null);
          setSeverityFilter(null);
        }}
      />
    </div>
  );
}
