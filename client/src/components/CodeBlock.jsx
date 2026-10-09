import React, { useState } from "react";
import { Copy, Check } from "lucide-react";

export default function CodeBlock({ code, title, language = "javascript" }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(typeof code === "string" ? code : JSON.stringify(code, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (_err) {
      // Fallback
    }
  };

  const formattedContent = typeof code === "string" ? code : JSON.stringify(code, null, 2);

  return (
    <div className="rounded-lg border border-slate-800 bg-[#070a11] overflow-hidden my-2">
      <div className="flex items-center justify-between px-3 py-1.5 bg-[#0e1320] border-b border-slate-800 text-xs text-slate-400">
        <span className="font-mono">{title || language}</span>
        <button
          onClick={handleCopy}
          className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-cyan-400 transition-colors py-0.5 px-2 rounded hover:bg-slate-800"
          title="Copy to clipboard"
        >
          {copied ? (
            <>
              <Check className="w-3.5 h-3.5 text-emerald-400" />
              <span className="text-emerald-400">Copied</span>
            </>
          ) : (
            <>
              <Copy className="w-3.5 h-3.5" />
              <span>Copy</span>
            </>
          )}
        </button>
      </div>
      <pre className="p-3 text-xs font-mono text-slate-200 overflow-x-auto max-h-72">
        <code>{formattedContent}</code>
      </pre>
    </div>
  );
}
