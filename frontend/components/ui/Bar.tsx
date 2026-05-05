// components/ui/Bar.tsx — Thin horizontal progress bar

interface BarProps {
  value: number;    // 0–1
  color?: string;
  height?: number;
}

export function Bar({ value, color = "var(--color-fg-0)", height = 2 }: BarProps) {
  const pct = Math.min(1, Math.max(0, value)) * 100;
  return (
    <div
      style={{
        width: "100%",
        height,
        background: "var(--color-ink-3)",
      }}
    >
      <div
        style={{
          height: "100%",
          width: `${pct}%`,
          background: color,
          transition: `width var(--normal) var(--ease)`,
        }}
      />
    </div>
  );
}

// Labelled bar row
export function LabelledBar({ label, value, color }: { label: string; value: number; color?: string }) {
  const pct = Math.min(1, Math.max(0, value)) * 100;
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
        <span className="label">{label}</span>
        <span
          style={{
            fontFamily: "var(--font-mono)",
            fontSize: "var(--text-11)",
            color: "var(--color-fg-2)",
          }}
        >
          {pct.toFixed(0)}
        </span>
      </div>
      <Bar value={value} color={color} />
    </div>
  );
}
