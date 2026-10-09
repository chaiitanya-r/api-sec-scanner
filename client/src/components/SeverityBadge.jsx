import React from "react";

const SEVERITY_CONFIG = {
  CRITICAL: {
    bg: "bg-red-500/10",
    text: "text-red-400",
    border: "border-red-500/30"
  },
  HIGH: {
    bg: "bg-orange-500/10",
    text: "text-orange-400",
    border: "border-orange-500/30"
  },
  MEDIUM: {
    bg: "bg-amber-500/10",
    text: "text-amber-400",
    border: "border-amber-500/30"
  },
  LOW: {
    bg: "bg-blue-500/10",
    text: "text-blue-400",
    border: "border-blue-500/30"
  },
  INFO: {
    bg: "bg-slate-500/10",
    text: "text-slate-400",
    border: "border-slate-500/30"
  }
};

export default function SeverityBadge({ severity }) {
  const norm = (severity || "INFO").toUpperCase();
  const config = SEVERITY_CONFIG[norm] || SEVERITY_CONFIG.INFO;

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold tracking-wide border ${config.bg} ${config.text} ${config.border}`}
    >
      {norm}
    </span>
  );
}
