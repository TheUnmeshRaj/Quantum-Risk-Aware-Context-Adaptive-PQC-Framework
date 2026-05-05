// components/dashboard/AlgorithmCard.tsx
import type { AnalyzeResponse } from "@/lib/types";
import { TierBadge } from "@/components/ui/StatusDot";
import { ScoreBar } from "@/components/ui/ScoreBar";

export function AlgorithmCard({ data }: { data: AnalyzeResponse }) {
  const gap = data.security_gap > 0;

  return (
    <div className="flex flex-col gap-5 animate-slide-up">
      {/* Header row */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="label-mono mb-1.5">Selected Algorithm</p>
          <p className="font-mono text-base font-semibold text-[var(--color-accent)]">
            {data.selected_algorithm}
          </p>
          <p className="text-xs text-[var(--color-text-secondary)] mt-1">
            {data.mode} · {data.security_level}
          </p>
        </div>
        <div className="text-right shrink-0">
          <p className="label-mono mb-1.5">QRI</p>
          <p className="data-value">{data.qri}</p>
          <TierBadge tier={data.qri_tier} />
        </div>
      </div>

      {/* NIST level bar */}
      <div className="flex flex-col gap-1">
        <div className="flex justify-between">
          <span className="label-mono">NIST Level</span>
          <span className="text-xs font-mono text-[var(--color-text-secondary)]">
            L{data.achieved_nist_level} / L5
          </span>
        </div>
        <div className="h-[3px] rounded-full bg-[var(--color-surface-2)]">
          <div
            className="h-full rounded-full"
            style={{
              width: `${(data.achieved_nist_level / 5) * 100}%`,
              backgroundColor: gap ? "var(--color-warning)" : "var(--color-success)",
              transition: "width var(--duration-normal) var(--ease-out)",
            }}
          />
        </div>
        {gap && (
          <p className="text-xs font-mono text-[var(--color-warning)] mt-0.5">
            ⚠ Gap {data.security_gap.toFixed(2)} — required L{data.required_nist_level}
          </p>
        )}
      </div>

      {/* Score breakdown */}
      <div className="flex flex-col gap-2 p-3 bg-[var(--color-surface-0)] rounded-[var(--radius-md)] border border-[var(--color-border-dim)]">
        <p className="label-mono mb-1">Scoring Breakdown</p>
        <ScoreBar label="Security Fit"   value={data.breakdown.security_fit} />
        <ScoreBar label="RAM Fit"        value={data.breakdown.ram_fit} />
        <ScoreBar label="Bandwidth Fit"  value={data.breakdown.bandwidth_fit} />
        <ScoreBar
          label="Final Score"
          value={data.breakdown.final_score}
          color="var(--color-accent)"
        />
      </div>

      {/* Reason */}
      <p className="text-xs text-[var(--color-text-secondary)] leading-relaxed border-l-2 border-[var(--color-border)] pl-3">
        {data.reason}
      </p>

      {/* Alternatives */}
      {data.alternatives.length > 0 && (
        <div>
          <p className="label-mono mb-2">Alternatives</p>
          <div className="flex flex-col gap-1">
            {data.alternatives.map((a) => (
              <div
                key={a.key}
                className="flex items-center justify-between px-3 py-2 bg-[var(--color-surface-0)] rounded-[var(--radius-sm)] border border-[var(--color-border-dim)]"
              >
                <span className="text-xs font-mono text-[var(--color-text-secondary)]">{a.key}</span>
                <div className="flex items-center gap-3">
                  <span className="label-mono">L{a.level}</span>
                  <span className="text-xs font-mono text-[var(--color-text-dim)]">
                    {a.score.toFixed(4)}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Rejected */}
      {data.rejected.length > 0 && (
        <details className="group">
          <summary className="label-mono cursor-pointer list-none flex items-center gap-1.5 hover:text-[var(--color-text-secondary)] transition-colors">
            <span className="group-open:rotate-90 transition-transform inline-block">▶</span>
            Rejected ({data.rejected.length})
          </summary>
          <div className="mt-2 flex flex-col gap-1">
            {data.rejected.map((r) => (
              <div
                key={r.algorithm}
                className="px-3 py-2 bg-[var(--color-surface-0)] rounded-[var(--radius-sm)] border-l-2 border-red-500/40"
              >
                <p className="text-xs font-mono text-red-400">{r.algorithm}</p>
                <p className="text-xs text-[var(--color-text-dim)] mt-0.5">{r.reason}</p>
              </div>
            ))}
          </div>
        </details>
      )}
    </div>
  );
}
