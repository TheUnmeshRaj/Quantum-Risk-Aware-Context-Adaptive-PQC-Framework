// components/ui/TierTag.tsx
import type { QriTier } from "@/lib/types";

const MAP: Record<QriTier, { color: string }> = {
  CRITICAL: { color: "var(--color-red)"    },
  HIGH:     { color: "var(--color-orange)" },
  ELEVATED: { color: "var(--color-yellow)" },
  MODERATE: { color: "var(--color-blue)"   },
  LOW:      { color: "var(--color-green)"  },
};

const RULE: Record<QriTier, string> = {
  CRITICAL: "tier-critical-rule",
  HIGH:     "tier-high-rule",
  ELEVATED: "tier-elevated-rule",
  MODERATE: "tier-moderate-rule",
  LOW:      "tier-low-rule",
};

export function TierTag({ tier }: { tier: QriTier }) {
  const { color } = MAP[tier] ?? MAP.MODERATE;
  return (
    <span
      style={{
        fontFamily: "var(--font-mono)",
        fontSize: "var(--text-10)",
        fontWeight: 600,
        letterSpacing: "0.1em",
        color,
        textTransform: "uppercase",
      }}
    >
      {tier}
    </span>
  );
}

export function tierRuleClass(tier: QriTier): string {
  return RULE[tier] ?? "tier-moderate-rule";
}

export function tierColor(tier: QriTier): string {
  return MAP[tier]?.color ?? "var(--color-blue)";
}

export function LiveStatus({ online }: { online: boolean }) {
  return (
    <span
      style={{
        fontFamily: "var(--font-mono)",
        fontSize: "var(--text-10)",
        letterSpacing: "0.1em",
        textTransform: "uppercase",
        color: online ? "var(--color-green)" : "var(--color-red)",
        display: "inline-flex",
        alignItems: "center",
        gap: 5,
      }}
    >
      <span
        className={online ? "blink" : ""}
        style={{
          display: "inline-block",
          width: 5,
          height: 5,
          background: online ? "var(--color-green)" : "var(--color-red)",
          borderRadius: "50%",
        }}
      />
      {online ? "ONLINE" : "OFFLINE"}
    </span>
  );
}
