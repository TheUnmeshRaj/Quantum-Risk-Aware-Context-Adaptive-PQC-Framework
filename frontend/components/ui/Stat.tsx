// components/ui/Stat.tsx
// Atomic stat block — label above, value below. Used in stat grids.

import type { ReactNode } from "react";

interface StatProps {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  color?: string;
  ruled?: boolean; // adds left rule for emphasis
}

export function Stat({ label, value, sub, color, ruled }: StatProps) {
  return (
    <div
      style={{
        padding: "16px 20px",
        borderLeft: ruled ? `2px solid ${color ?? "var(--color-fg-0)"}` : undefined,
        display: "flex",
        flexDirection: "column",
        gap: 8,
      }}
    >
      <div className="label">{label}</div>
      <div
        style={{
          fontFamily: "var(--font-mono)",
          fontSize: "var(--text-20)",
          fontWeight: 600,
          letterSpacing: "-0.02em",
          color: color ?? "var(--color-fg-0)",
          lineHeight: 1,
        }}
      >
        {value}
      </div>
      {sub && (
        <div
          style={{
            fontFamily: "var(--font-mono)",
            fontSize: "var(--text-11)",
            color: "var(--color-fg-2)",
          }}
        >
          {sub}
        </div>
      )}
    </div>
  );
}
