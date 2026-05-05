"use client";
// app/(dashboard)/fleet/FleetContent.tsx

import { useState } from "react";
import { api } from "@/lib/api";
import { DEVICE_PROFILES } from "@/lib/fixtures";
import { Stat } from "@/components/ui/Stat";
import { Skel } from "@/components/ui/Skeleton";
import { TierTag, tierColor } from "@/components/ui/TierTag";
import { Bar } from "@/components/ui/Bar";
import type { SimulateResponse } from "@/lib/types";

const ADVERSARY_OPTIONS = ["low", "medium", "nation_state"] as const;

export function FleetContent() {
  const [adversary, setAdversary] = useState<"low" | "medium" | "nation_state">("medium");
  const [result,    setResult]    = useState<SimulateResponse | null>(null);
  const [loading,   setLoading]   = useState(false);
  const [error,     setError]     = useState<string | null>(null);

  async function run() {
    setLoading(true); setError(null);
    try {
      const payload = DEVICE_PROFILES.map((p) => ({
        ...p, adversary,
        hardware: { ...p.hardware, ram_kb: Math.min(p.hardware.ram_kb, 2_000_000) },
      }));
      setResult(await api.simulate(payload));
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "error");
    } finally { setLoading(false); }
  }

  const fm = result?.fleet_metrics;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 24, maxWidth: 1200 }}>

      {/* ── Toolbar ── */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 0,
          borderBottom: "1px solid var(--color-rule)",
          paddingBottom: 16,
        }}
      >
        <div style={{ display: "flex", gap: 0, marginRight: 20 }}>
          {ADVERSARY_OPTIONS.map((a) => (
            <button
              key={a}
              onClick={() => { setAdversary(a); setResult(null); }}
              style={{
                fontFamily: "var(--font-mono)",
                fontSize: "var(--text-11)",
                letterSpacing: "0.06em",
                textTransform: "uppercase",
                padding: "6px 14px",
                background: adversary === a ? "var(--color-fg-0)" : "transparent",
                color: adversary === a ? "var(--color-ink-0)" : "var(--color-fg-2)",
                border: "1px solid var(--color-rule)",
                borderRight: "none",
                cursor: "pointer",
                transition: "all var(--fast) var(--ease)",
              }}
            >
              {a}
            </button>
          ))}
          <div style={{ width: 1, background: "var(--color-rule)" }} />
        </div>

        <button
          onClick={run}
          disabled={loading}
          style={{
            fontFamily: "var(--font-mono)",
            fontSize: "var(--text-11)",
            letterSpacing: "0.08em",
            textTransform: "uppercase",
            padding: "6px 20px",
            background: loading ? "var(--color-ink-2)" : "var(--color-fg-0)",
            color: loading ? "var(--color-fg-2)" : "var(--color-ink-0)",
            border: "none",
            fontWeight: 700,
            cursor: loading ? "not-allowed" : "pointer",
            transition: "all var(--fast) var(--ease)",
          }}
        >
          {loading ? "SIMULATING…" : `RUN /SIMULATE · ${DEVICE_PROFILES.length} DEVICES`}
        </button>

        {error && (
          <span
            style={{
              marginLeft: 16,
              fontFamily: "var(--font-mono)",
              fontSize: "var(--text-11)",
              color: "var(--color-red)",
            }}
          >
            {error}
          </span>
        )}
      </div>

      {/* ── KPI strip ── */}
      {loading && !fm ? (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", border: "1px solid var(--color-rule)" }}>
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} style={{ padding: 20, borderRight: i < 4 ? "1px solid var(--color-rule)" : undefined }}>
              <Skel h={8} w={50} />
              <div style={{ marginTop: 12 }}><Skel h={22} w={70} /></div>
            </div>
          ))}
        </div>
      ) : fm ? (
        <div
          className="fade-in"
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(5, 1fr)",
            border: "1px solid var(--color-rule)",
          }}
        >
          <Stat label="DEVICES"    value={fm.device_count}              ruled />
          <Stat label="AVG QRI"    value={fm.avg_qri}                   sub={`max ${fm.max_qri}`} />
          <Stat label="CRITICAL"   value={fm.critical_count}            color={fm.critical_count > 0 ? "var(--color-red)" : undefined} sub={`${fm.high_count} HIGH`} />
          <Stat label="COMPLIANCE" value={`${fm.avg_compliance_score}%`} />
          <Stat label="TOTAL TIME" value={`${fm.total_processing_ms.toFixed(1)}ms`} />
        </div>
      ) : null}

      {/* ── Fleet table ── */}
      {result && (
        <div className="fade-in" style={{ border: "1px solid var(--color-rule)", overflowX: "auto" }}>
          {/* Header */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "2fr 80px 2fr 60px 100px 80px",
              padding: "8px 16px",
              background: "var(--color-ink-2)",
              borderBottom: "1px solid var(--color-rule)",
              minWidth: "600px",
            }}
          >
            {["DEVICE", "QRI", "ALGORITHM", "NIST", "COMPLIANCE", "TIME"].map((h) => (
              <span key={h} className="label">{h}</span>
            ))}
          </div>

          {result.results.map((r) => {
            const compliance = r.achieved_nist_level / 5;
            const compColor = compliance >= 0.8 ? "var(--color-green)" : compliance >= 0.6 ? "var(--color-yellow)" : "var(--color-red)";
            return (
              <div
                key={r.device}
                className="hover-surface"
                style={{
                  display: "grid",
                  gridTemplateColumns: "2fr 80px 2fr 60px 100px 80px",
                  padding: "12px 16px",
                  borderBottom: "1px solid var(--color-rule-dim)",
                  borderLeft: `2px solid ${tierColor(r.qri_tier)}`,
                  alignItems: "center",
                  transition: "background var(--fast) var(--ease)",
                  minWidth: "600px",
                }}
              >
                <div>
                  <div style={{ fontFamily: "var(--font-sans)", fontSize: "var(--text-13)", fontWeight: 500, color: "var(--color-fg-0)", marginBottom: 2 }}>
                    {r.device}
                  </div>
                  <TierTag tier={r.qri_tier} />
                </div>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-14)", fontWeight: 700, color: tierColor(r.qri_tier) }}>
                  {r.qri}
                </span>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-11)", color: "var(--color-fg-1)" }}>
                  {r.selected_algorithm}
                </span>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-13)", color: "var(--color-fg-0)" }}>
                  L{r.achieved_nist_level}
                  {r.security_gap > 0 && <span style={{ color: "var(--color-yellow)", marginLeft: 4 }}>⚠</span>}
                </span>
                <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                  <span className="label" style={{ color: compColor }}>{Math.round(compliance * 100)}%</span>
                  <Bar value={compliance} color={compColor} height={2} />
                </div>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-11)", color: "var(--color-fg-2)", textAlign: "right" }}>
                  {r.processing_time_ms.toFixed(1)}ms
                </span>
              </div>
            );
          })}
        </div>
      )}

      {!result && !loading && (
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            minHeight: 200,
            border: "1px solid var(--color-rule-dim)",
          }}
        >
          <span className="label">SELECT ADVERSARY MODEL → RUN /SIMULATE</span>
        </div>
      )}

    </div>
  );
}
