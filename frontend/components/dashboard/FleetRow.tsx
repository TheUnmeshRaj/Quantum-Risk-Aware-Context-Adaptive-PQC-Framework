// components/dashboard/FleetRow.tsx
import type { AnalyzeResponse } from "@/lib/types";
import { TierBadge } from "@/components/ui/StatusDot";

const TIER_BORDER: Record<string, string> = {
  CRITICAL: "border-l-red-500",
  HIGH:     "border-l-orange-500",
  ELEVATED: "border-l-yellow-400",
  MODERATE: "border-l-blue-500",
  LOW:      "border-l-green-500",
};

export function FleetRow({ r, rank }: { r: AnalyzeResponse; rank: number }) {
  const border = TIER_BORDER[r.qri_tier] ?? "border-l-slate-600";
  const compliance = Math.round((r.achieved_nist_level / 5) * 100);

  return (
    <div
      className={`
        grid grid-cols-[2fr_1fr_2fr_1fr_1fr_80px] items-center
        gap-4 px-4 py-3
        border-l-2 ${border}
        bg-[var(--color-surface-1)]
        border-b border-[var(--color-border-dim)]
        last:border-b-0
        hover:bg-[var(--color-surface-2)] transition-colors
      `}
    >
      {/* Device */}
      <div>
        <p className="text-xs font-semibold text-[var(--color-text-primary)] truncate">{r.device}</p>
        <TierBadge tier={r.qri_tier} />
      </div>

      {/* QRI */}
      <span className="data-value text-base">{r.qri}</span>

      {/* Algorithm */}
      <span className="text-xs font-mono text-[var(--color-accent)] truncate">{r.selected_algorithm}</span>

      {/* NIST */}
      <span className="text-xs font-mono text-[var(--color-text-secondary)]">
        L{r.achieved_nist_level}
        {r.security_gap > 0 && (
          <span className="text-yellow-400 ml-1">⚠</span>
        )}
      </span>

      {/* Compliance */}
      <div className="flex flex-col gap-1">
        <span className="label-mono">{compliance}%</span>
        <div className="h-[2px] rounded-full bg-[var(--color-surface-0)]">
          <div
            className="h-full rounded-full"
            style={{
              width: `${compliance}%`,
              backgroundColor: compliance >= 80 ? "var(--color-success)" : compliance >= 60 ? "var(--color-warning)" : "var(--color-critical)",
            }}
          />
        </div>
      </div>

      {/* Time */}
      <span className="label-mono text-right">{r.processing_time_ms.toFixed(1)}ms</span>
    </div>
  );
}
