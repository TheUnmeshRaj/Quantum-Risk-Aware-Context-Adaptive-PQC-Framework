"use client";
// app/(dashboard)/analyze/AnalyzeContent.tsx

import { useState } from "react";
import { api } from "@/lib/api";
import { DEVICE_PROFILES } from "@/lib/fixtures";
import { AlgorithmResult } from "@/components/dashboard/AlgorithmResult";
import { Stat } from "@/components/ui/Stat";
import type { AnalyzeResponse, DeviceProfileRequest } from "@/lib/types";

const ADVERSARY = ["low", "medium", "nation_state"] as const;

export function AnalyzeContent() {
  const [idx,       setIdx]       = useState(0);
  const [adversary, setAdversary] = useState<"low" | "medium" | "nation_state">("medium");
  const [result,    setResult]    = useState<AnalyzeResponse | null>(null);
  const [loading,   setLoading]   = useState(false);
  const [error,     setError]     = useState<string | null>(null);

  const base = DEVICE_PROFILES[idx];
  const payload: DeviceProfileRequest = {
    ...base,
    adversary,
    hardware: { ...base.hardware, ram_kb: Math.min(base.hardware.ram_kb, 2_000_000) },
  };

  async function run() {
    setLoading(true); setError(null);
    try { setResult(await api.analyze(payload)); }
    catch (e: unknown) { setError(e instanceof Error ? e.message : "error"); }
    finally { setLoading(false); }
  }

  const S: React.CSSProperties = {
    fontFamily: "var(--font-mono)",
    fontSize: "var(--text-12)",
    color: "var(--color-fg-1)",
  };

  return (
    <div style={{ display: "grid", gridTemplateColumns: "220px 1fr", gap: 0, maxWidth: 1100 }}>

      {/* ── Controls ── */}
      <aside
        style={{
          borderRight: "1px solid var(--color-rule)",
          paddingRight: 24,
          display: "flex",
          flexDirection: "column",
          gap: 20,
        }}
      >
        {/* Device */}
        <div>
          <div className="label" style={{ marginBottom: 8 }}>DEVICE PROFILE</div>
          <select
            value={idx}
            onChange={(e) => { setIdx(Number(e.target.value)); setResult(null); }}
            style={{ ...S, width: "100%", padding: "8px 10px", cursor: "pointer" }}
          >
            {DEVICE_PROFILES.map((d, i) => <option key={i} value={i}>{d.name}</option>)}
          </select>
        </div>

        {/* Adversary */}
        <div>
          <div className="label" style={{ marginBottom: 8 }}>ADVERSARY MODEL</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
            {ADVERSARY.map((a) => (
              <button
                key={a}
                onClick={() => { setAdversary(a); setResult(null); }}
                style={{
                  ...S,
                  textAlign: "left",
                  padding: "8px 10px",
                  background: adversary === a ? "var(--color-ink-3)" : "transparent",
                  border: "none",
                  borderLeft: adversary === a ? "2px solid var(--color-fg-0)" : "2px solid transparent",
                  color: adversary === a ? "var(--color-fg-0)" : "var(--color-fg-2)",
                  cursor: "pointer",
                  transition: "all var(--fast) var(--ease)",
                }}
              >
                {a}
              </button>
            ))}
          </div>
        </div>

        {/* Profile summary */}
        <div style={{ borderTop: "1px solid var(--color-rule-dim)", paddingTop: 16 }}>
          <div className="label" style={{ marginBottom: 10 }}>PARAMETERS</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {[
              ["SENSITIVITY", base.data_sensitivity],
              ["EXPOSURE",    base.exposure_level],
              ["LIFETIME",    `${base.data_lifetime_yrs}yr`],
              ["THREAT WIN",  base.threat_window],
              ["RAM",         `${(Math.min(base.hardware.ram_kb, 2_000_000) / 1024).toFixed(0)} MB`],
            ].map(([k, v]) => (
              <div key={String(k)} style={{ display: "flex", justifyContent: "space-between" }}>
                <span className="label">{k}</span>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-11)", color: "var(--color-fg-1)" }}>{v}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Run */}
        <button
          onClick={run}
          disabled={loading}
          style={{
            padding: "10px",
            fontFamily: "var(--font-mono)",
            fontSize: "var(--text-12)",
            fontWeight: 700,
            letterSpacing: "0.08em",
            textTransform: "uppercase" as const,
            background: loading ? "var(--color-ink-2)" : "var(--color-fg-0)",
            color: loading ? "var(--color-fg-2)" : "var(--color-ink-0)",
            border: "none",
            cursor: loading ? "not-allowed" : "pointer",
            transition: "all var(--fast) var(--ease)",
          }}
        >
          {loading ? "ANALYZING…" : "RUN /ANALYZE"}
        </button>

        {error && (
          <div
            style={{
              padding: "8px 10px",
              borderLeft: "2px solid var(--color-red)",
              fontFamily: "var(--font-mono)",
              fontSize: "var(--text-11)",
              color: "var(--color-red)",
            }}
          >
            {error}
          </div>
        )}
      </aside>

      {/* ── Result ── */}
      <div style={{ paddingLeft: 24 }}>
        {result ? (
          <div className="fade-in" style={{ display: "flex", flexDirection: "column", gap: 0 }}>
            {/* KPI strip */}
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(3, 1fr)",
                border: "1px solid var(--color-rule)",
                borderBottom: "none",
              }}
            >
              <Stat label="QRI Score"     value={result.qri}    sub={result.qri_tier} ruled />
              <Stat label="Required L"    value={`L${result.required_nist_level}`} />
              <Stat label="Process Time"  value={`${result.processing_time_ms.toFixed(2)}ms`} />
            </div>
            {/* Main result */}
            <div style={{ border: "1px solid var(--color-rule)" }}>
              <AlgorithmResult data={result} />
            </div>
          </div>
        ) : (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              minHeight: 300,
              border: "1px solid var(--color-rule-dim)",
            }}
          >
            <span className="label">SELECT DEVICE → RUN /ANALYZE</span>
          </div>
        )}
      </div>

    </div>
  );
}
