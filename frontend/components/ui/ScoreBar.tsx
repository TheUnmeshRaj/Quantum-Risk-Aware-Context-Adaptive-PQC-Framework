// components/ui/ScoreBar.tsx

interface ScoreBarProps {
  label: string;
  value: number; // 0–1
  color?: string;
}

export function ScoreBar({ label, value, color = "var(--color-accent)" }: ScoreBarProps) {
  const pct = Math.min(1, Math.max(0, value)) * 100;
  return (
    <div className="flex flex-col gap-1">
      <div className="flex justify-between items-baseline">
        <span className="label-mono">{label}</span>
        <span className="text-xs font-mono text-[var(--color-text-secondary)]">
          {pct.toFixed(0)}%
        </span>
      </div>
      <div className="h-[3px] rounded-full bg-[var(--color-surface-2)] overflow-hidden">
        <div
          className="h-full rounded-full transition-all"
          style={{ width: `${pct}%`, backgroundColor: color, transitionDuration: "var(--duration-normal)" }}
        />
      </div>
    </div>
  );
}
