import { useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { Download, FileText, ChevronDown } from "lucide-react";
import { AnimatePresence, motion } from "framer-motion";
import { CopyButton } from "./ui/Primitives";

export default function ReportView({ markdown }: { markdown: string }) {
  const [open, setOpen] = useState(false);

  function download() {
    const blob = new Blob([markdown], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "intent-aware-report.md";
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="glass overflow-hidden">
      <div className="flex items-center justify-between p-4">
        <button
          type="button"
          onClick={() => setOpen((o) => !o)}
          className="flex items-center gap-2 font-display text-sm font-semibold text-fg"
          aria-expanded={open}
          aria-controls="report-panel"
        >
          <FileText size={16} className="text-brand-cyan" />
          Full report
          <ChevronDown size={16} className={`text-fg-subtle transition-transform ${open ? "rotate-180" : ""}`} />
        </button>
        <div className="flex gap-2">
          <CopyButton text={markdown} label="Copy markdown" />
          <button type="button" onClick={download} className="btn-ghost px-2.5 py-1.5 text-xs">
            <Download size={14} /> .md
          </button>
        </div>
      </div>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            id="report-panel"
            role="region"
            aria-label="Full report"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.3 }}
            className="overflow-hidden"
          >
            <div className="prose-report max-h-[460px] overflow-auto border-t border-line p-5 text-sm">
              <ReactMarkdown
                remarkPlugins={[remarkGfm]}
                components={{ a: ({ node, ...p }) => <a {...p} target="_blank" rel="noreferrer noopener" /> }}
              >
                {markdown}
              </ReactMarkdown>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
