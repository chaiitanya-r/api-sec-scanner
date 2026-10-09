import React from "react";
import { ShieldAlert, AlertTriangle, AlertCircle, Info, ShieldCheck } from "lucide-react";

export default function SummaryCards({ summary = {}, activeFilter, onSelectFilter }) {
  const cards = [
    {
      key: "CRITICAL",
      label: "Critical",
      count: summary.critical || 0,
      color: "text-red-400",
      border: "border-red-500/30",
      bg: "bg-red-500/5",
      icon: ShieldAlert
    },
    {
      key: "HIGH",
      label: "High",
      count: summary.high || 0,
      color: "text-orange-400",
      border: "border-orange-500/30",
      bg: "bg-orange-500/5",
      icon: AlertTriangle
    },
    {
      key: "MEDIUM",
      label: "Medium",
      count: summary.medium || 0,
      color: "text-amber-400",
      border: "border-amber-500/30",
      bg: "bg-amber-500/5",
      icon: AlertCircle
    },
    {
      key: "LOW",
      label: "Low",
      count: summary.low || 0,
      color: "text-blue-400",
      border: "border-blue-500/30",
      bg: "bg-blue-500/5",
      icon: Info
    },
    {
      key: "INFO",
      label: "Info",
      count: summary.info || 0,
      color: "text-slate-400",
      border: "border-slate-500/30",
      bg: "bg-slate-500/5",
      icon: ShieldCheck
    }
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mb-6">
      {cards.map((c) => {
        const Icon = c.icon;
        const isSelected = activeFilter === c.key;

        return (
          <button
            key={c.key}
            onClick={() => onSelectFilter(isSelected ? null : c.key)}
            className={`flex flex-col p-4 rounded-xl border text-left transition-all ${c.bg} ${c.border} ${
              isSelected ? "ring-2 ring-cyan-500 shadow-lg shadow-cyan-500/10" : "hover:border-slate-700 hover:scale-[1.02]"
            }`}
          >
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-xs font-semibold tracking-wider uppercase">{c.label}</span>
              <Icon className={`w-4 h-4 ${c.color}`} />
            </div>
            <div className={`text-2xl font-bold ${c.color}`}>{c.count}</div>
            <div className="text-[11px] text-slate-500 mt-1">
              {isSelected ? "Filter active (click to reset)" : "Click to filter"}
            </div>
          </button>
        );
      })}
    </div>
  );
}
