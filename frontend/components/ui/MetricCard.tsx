// components/ui/MetricCard.tsx
import type { ReactNode } from "react";

interface MetricCardProps {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  accent?: boolean;
  className?: string;
}

export function MetricCard({ label, value, sub, accent, className = "" }: MetricCardProps) {
  return (
    <div
      className={`
        flex flex-col gap-2 p-4
        bg-[var(--color-surface-1)]
        border border-[var(--color-border-dim)]
        rounded-[var(--radius-lg)]
        ${accent ? "border-l-2 border-l-[var(--color-accent)]" : ""}
        ${className}
      `}
    >
      <span className="label-mono">{label}</span>
      <span className="data-value">{value}</span>
      {sub && <span className="text-xs text-[var(--color-text-dim)] font-mono">{sub}</span>}
    </div>
  );
}
