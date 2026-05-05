// components/ui/StatusDot.tsx
import type { QriTier } from "@/lib/types";

const TIER_MAP: Record<QriTier, { dot: string; label: string }> = {
  CRITICAL: { dot: "bg-red-500",    label: "tier-critical" },
  HIGH:     { dot: "bg-orange-500", label: "tier-high" },
  ELEVATED: { dot: "bg-yellow-400", label: "tier-elevated" },
  MODERATE: { dot: "bg-blue-500",   label: "tier-moderate" },
  LOW:      { dot: "bg-green-500",  label: "tier-low" },
};

export function TierBadge({ tier }: { tier: QriTier }) {
  const { dot, label } = TIER_MAP[tier] ?? TIER_MAP.MODERATE;
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs font-mono font-medium ${label}`}>
      <span className={`inline-block w-1.5 h-1.5 rounded-full ${dot}`} />
      {tier}
    </span>
  );
}

export function LiveDot({ online }: { online: boolean }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-mono">
      <span
        className={`inline-block w-1.5 h-1.5 rounded-full ${
          online ? "bg-green-400 pulse-dot" : "bg-red-500"
        }`}
      />
      {online ? "ONLINE" : "OFFLINE"}
    </span>
  );
}
