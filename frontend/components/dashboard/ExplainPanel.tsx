// components/dashboard/ExplainPanel.tsx
import type { ExplainResponse } from "@/lib/types";

const STEP_ICONS = ["①", "②", "③", "④", "⑤", "⑥", "⑦", "⑧"];

export function ExplainPanel({ data }: { data: ExplainResponse }) {
  return (
    <div className="flex flex-col gap-4 animate-slide-up">
      <div className="grid grid-cols-2 gap-3">
        <div className="p-3 bg-[var(--color-surface-0)] rounded-[var(--radius-md)] border border-[var(--color-border-dim)]">
          <p className="label-mono mb-1">QRI</p>
          <p className="data-value text-xl">{data.qri}</p>
        </div>
        <div className="p-3 bg-[var(--color-surface-0)] rounded-[var(--radius-md)] border border-[var(--color-border-dim)]">
          <p className="label-mono mb-1">Required Level</p>
          <p className="data-value text-xl">L{data.required_level.toFixed(2)}</p>
        </div>
      </div>

      <div className="flex flex-col gap-1">
        <p className="label-mono mb-1">Decision Walkthrough</p>
        {data.step_by_step.map((step, i) => (
          <div
            key={i}
            className="flex gap-2.5 px-3 py-2.5 bg-[var(--color-surface-0)] rounded-[var(--radius-sm)] border-l-2 border-[var(--color-border)]"
            style={{ animationDelay: `${i * 40}ms` }}
          >
            <span className="text-[var(--color-text-dim)] font-mono text-xs shrink-0 mt-px">
              {STEP_ICONS[i] ?? `${i + 1}.`}
            </span>
            <p className="text-xs text-[var(--color-text-secondary)] leading-relaxed">{step}</p>
          </div>
        ))}
      </div>

      <div className="p-3 bg-[var(--color-accent-dim)] border border-[var(--color-accent-border)] rounded-[var(--radius-md)]">
        <p className="label-mono text-[var(--color-accent)] mb-1">Final Selection</p>
        <p className="text-sm font-mono font-semibold text-[var(--color-accent)]">{data.selected}</p>
        <p className="text-xs text-[var(--color-text-secondary)] mt-1.5 leading-relaxed">{data.selected_reason}</p>
      </div>
    </div>
  );
}
