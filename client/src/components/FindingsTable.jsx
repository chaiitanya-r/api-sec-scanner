import React, { useState, useMemo } from "react";
import { Search, ArrowUpDown, ChevronRight, Filter } from "lucide-react";
import SeverityBadge from "./SeverityBadge.jsx";

const SEVERITY_RANKS = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1
};

export default function FindingsTable({
  findings = [],
  selectedFinding,
  onSelectFinding,
  severityFilter,
  onClearFilter
}) {
  const [searchTerm, setSearchTerm] = useState("");
  const [methodFilter, setMethodFilter] = useState("ALL");
  const [sortField, setSortField] = useState("severity"); // severity | cvss | endpoint
  const [sortAsc, setSortAsc] = useState(false);

  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      // Severity filter
      if (severityFilter && f.severity?.toUpperCase() !== severityFilter.toUpperCase()) {
        return false;
      }

      // Method filter
      if (methodFilter !== "ALL" && f.method?.toUpperCase() !== methodFilter) {
        return false;
      }

      // Search term
      if (searchTerm) {
        const query = searchTerm.toLowerCase();
        const matchTitle = f.title?.toLowerCase().includes(query);
        const matchEndpoint = f.endpoint?.toLowerCase().includes(query);
        const matchId = f.id?.toLowerCase().includes(query);
        if (!matchTitle && !matchEndpoint && !matchId) {
          return false;
        }
      }

      return true;
    }).sort((a, b) => {
      let cmp = 0;
      if (sortField === "severity") {
        const rankA = SEVERITY_RANKS[a.severity?.toUpperCase()] || 0;
        const rankB = SEVERITY_RANKS[b.severity?.toUpperCase()] || 0;
        cmp = rankA - rankB;
      } else if (sortField === "cvss") {
        cmp = (a.cvssScore || 0) - (b.cvssScore || 0);
      } else if (sortField === "endpoint") {
        cmp = (a.endpoint || "").localeCompare(b.endpoint || "");
      } else if (sortField === "title") {
        cmp = (a.title || "").localeCompare(b.title || "");
      }
      return sortAsc ? cmp : -cmp;
    });
  }, [findings, severityFilter, methodFilter, searchTerm, sortField, sortAsc]);

  const handleSort = (field) => {
    if (sortField === field) {
      setSortAsc(!sortAsc);
    } else {
      setSortField(field);
      setSortAsc(false); // Default descending for severity and cvss
    }
  };

  return (
    <div className="bg-[#111622] border border-slate-800 rounded-xl overflow-hidden shadow-xl">
      {/* Controls Bar */}
      <div className="p-4 border-b border-slate-800 flex flex-wrap gap-3 items-center justify-between">
        <div className="flex items-center gap-2 flex-1 min-w-[240px]">
          <div className="relative w-full max-w-md">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search by endpoint, title, or ID..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 bg-[#090d15] border border-slate-800 rounded-lg text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          {/* Method Filter */}
          <div className="flex items-center gap-1.5 text-xs text-slate-400">
            <Filter className="w-3.5 h-3.5" />
            <select
              value={methodFilter}
              onChange={(e) => setMethodFilter(e.target.value)}
              className="bg-[#090d15] border border-slate-800 text-slate-200 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Methods</option>
              <option value="GET">GET</option>
              <option value="POST">POST</option>
              <option value="PUT">PUT</option>
              <option value="DELETE">DELETE</option>
              <option value="PATCH">PATCH</option>
            </select>
          </div>

          {severityFilter && (
            <button
              onClick={onClearFilter}
              className="text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 px-2.5 py-1.5 rounded-lg transition-colors"
            >
              Clear Severity ({severityFilter}) ✕
            </button>
          )}
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-slate-800 bg-[#0d121c] text-[11px] font-bold text-slate-400 uppercase tracking-wider">
              <th className="py-3 px-4 cursor-pointer hover:text-slate-200" onClick={() => handleSort("severity")}>
                <div className="flex items-center gap-1">
                  Severity
                  <ArrowUpDown className="w-3 h-3" />
                </div>
              </th>
              <th className="py-3 px-4 cursor-pointer hover:text-slate-200" onClick={() => handleSort("title")}>
                <div className="flex items-center gap-1">
                  Finding Title
                  <ArrowUpDown className="w-3 h-3" />
                </div>
              </th>
              <th className="py-3 px-4">Method</th>
              <th className="py-3 px-4 cursor-pointer hover:text-slate-200" onClick={() => handleSort("endpoint")}>
                <div className="flex items-center gap-1">
                  Endpoint
                  <ArrowUpDown className="w-3 h-3" />
                </div>
              </th>
              <th className="py-3 px-4 cursor-pointer hover:text-slate-200 text-right" onClick={() => handleSort("cvss")}>
                <div className="flex items-center justify-end gap-1">
                  CVSS Score
                  <ArrowUpDown className="w-3 h-3" />
                </div>
              </th>
              <th className="py-3 px-4 text-center">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 text-xs">
            {filteredFindings.length === 0 ? (
              <tr>
                <td colSpan={6} className="py-12 text-center text-slate-500">
                  No security findings match current filters.
                </td>
              </tr>
            ) : (
              filteredFindings.map((finding) => {
                const isSelected = selectedFinding?.id === finding.id && selectedFinding?.endpoint === finding.endpoint;

                return (
                  <tr
                    key={`${finding.id}-${finding.endpoint}-${finding.method}`}
                    onClick={() => onSelectFinding(finding)}
                    className={`cursor-pointer transition-colors ${
                      isSelected
                        ? "bg-cyan-950/30 text-white"
                        : "hover:bg-slate-800/40 text-slate-300"
                    }`}
                  >
                    <td className="py-3 px-4 whitespace-nowrap">
                      <SeverityBadge severity={finding.severity} />
                    </td>
                    <td className="py-3 px-4 font-medium text-slate-200 max-w-xs truncate">
                      <div className="truncate">{finding.title}</div>
                      <div className="text-[10px] font-mono text-slate-500">{finding.id}</div>
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      <span className="font-mono font-bold text-[11px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-200 border border-slate-700">
                        {finding.method}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-mono text-cyan-400 whitespace-nowrap max-w-sm truncate">
                      {finding.endpoint}
                    </td>
                    <td className="py-3 px-4 font-mono font-bold text-right whitespace-nowrap">
                      {finding.cvssScore !== undefined ? finding.cvssScore.toFixed(1) : "0.0"}
                    </td>
                    <td className="py-3 px-4 text-center whitespace-nowrap">
                      <ChevronRight className="w-4 h-4 text-slate-500 inline group-hover:text-cyan-400" />
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      <div className="p-3 bg-[#0d121c] border-t border-slate-800 text-[11px] text-slate-500 flex justify-between items-center">
        <span>Showing {filteredFindings.length} of {findings.length} findings</span>
        <span>Click any row to inspect request/response evidence and fixes</span>
      </div>
    </div>
  );
}
