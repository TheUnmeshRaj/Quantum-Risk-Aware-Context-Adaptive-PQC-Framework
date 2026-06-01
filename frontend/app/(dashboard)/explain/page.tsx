"use client";
// app/(dashboard)/explain/page.tsx

import { Topbar } from "@/components/layout/Topbar";
import { useState } from "react";
import { api } from "@/lib/api";
import { useProfiles } from "@/context/ProfilesContext";
import type { ExplainResponse, DeviceProfileRequest } from "@/lib/types";

const STEP_NUM = ["01", "02", "03", "04", "05", "06", "07", "08"];

export default function ExplainPage() {
  const { profiles } = useProfiles();
  const [idx,       setIdx]       = useState(0);
  const [adversary, setAdversary] = useState<"low" | "medium" | "nation_state">("medium");
  const [result,    setResult]    = useState<ExplainResponse | null>(null);
  const [loading,   setLoading]   = useState(false);
  const [error,     setError]     = useState<string | null>(null);

  const base = profiles[idx] || profiles[0];
  const payload: DeviceProfileRequest = base ? {
    ...base, adversary,
    hardware: { ...base.hardware, ram_kb: Math.min(base.hardware.ram_kb, 2_000_000) },
  } : {
    name: "Default",
    data_sensitivity: 5,
    exposure_level: 5,
    data_lifetime_yrs: 5,
    threat_window: 5,
    adversary: "medium",
    hardware: { ram_kb: 512, cpu: "ARM", has_fpu: false, bandwidth_kbps: 100 }
  };

  async function run() {
    setLoading(true); setError(null);
    try { setResult(await api.explain(payload)); }
    catch (e: unknown) { setError(e instanceof Error ? e.message : "error"); }
    finally { setLoading(false); }
  }

  return (
    <>
      <Topbar title="Explain" sub="/explain — step-by-step decision walkthrough" />
      <main style={{ padding: 24, flex: 1 }}>
        <div style={{ display: "grid", gridTemplateColumns: "220px 1fr", gap: 0, maxWidth: 1000 }}>

          {/* Controls */}
          <aside
            style={{
              borderRight: "1px solid var(--color-rule)",
              paddingRight: 24,
              display: "flex",
              flexDirection: "column",
              gap: 20,
            }}
          >
            <div>
              <div className="label" style={{ marginBottom: 8 }}>DEVICE</div>
              <select
                value={idx}
                onChange={(e) => { setIdx(Number(e.target.value)); setResult(null); }}
                style={{
                  fontFamily: "var(--font-mono)", fontSize: "var(--text-12)",
                  width: "100%", padding: "8px 10px", cursor: "pointer",
                  background: "var(--color-ink-2)", color: "var(--color-fg-0)",
                  border: "1px solid var(--color-rule)", borderRadius: 0,
                }}
              >
                {profiles.map((d, i) => <option key={i} value={i}>{d.name}</option>)}
              </select>
            </div>

            <div>
              <div className="label" style={{ marginBottom: 8 }}>ADVERSARY</div>
              {(["low", "medium", "nation_state"] as const).map((a) => (
                <button
                  key={a}
                  onClick={() => { setAdversary(a); setResult(null); }}
                  style={{
                    display: "block", width: "100%", textAlign: "left",
                    fontFamily: "var(--font-mono)", fontSize: "var(--text-12)",
                    padding: "8px 10px", marginBottom: 2,
                    background: adversary === a ? "var(--color-ink-3)" : "transparent",
                    color: adversary === a ? "var(--color-fg-0)" : "var(--color-fg-2)",
                    border: "none",
                    borderLeft: adversary === a ? "2px solid var(--color-fg-0)" : "2px solid transparent",
                    cursor: "pointer",
                    transition: "all var(--fast) var(--ease)",
                  }}
                >
                  {a}
                </button>
              ))}
            </div>

            <button
              onClick={run}
              disabled={loading}
              style={{
                padding: "10px",
                fontFamily: "var(--font-mono)", fontSize: "var(--text-12)",
                fontWeight: 700, letterSpacing: "0.08em", textTransform: "uppercase",
                background: loading ? "var(--color-ink-2)" : "var(--color-fg-0)",
                color: loading ? "var(--color-fg-2)" : "var(--color-ink-0)",
                border: "none", cursor: loading ? "not-allowed" : "pointer",
                transition: "all var(--fast) var(--ease)",
              }}
            >
              {loading ? "COMPUTING…" : "RUN /EXPLAIN"}
            </button>

            {error && (
              <div style={{ padding: "8px 10px", borderLeft: "2px solid var(--color-red)", fontFamily: "var(--font-mono)", fontSize: "var(--text-11)", color: "var(--color-red)" }}>
                {error}
              </div>
            )}
          </aside>

          {/* Result */}
          <div style={{ paddingLeft: 24 }}>
            {result ? (
              <div className="fade-in" style={{ display: "flex", flexDirection: "column" }}>

                {/* QRI / Level */}
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", border: "1px solid var(--color-rule)", borderBottom: "none" }}>
                  <div style={{ padding: "16px 20px", borderRight: "1px solid var(--color-rule)" }}>
                    <div className="label" style={{ marginBottom: 8 }}>QRI</div>
                    <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-28)", fontWeight: 600, color: "var(--color-fg-0)", lineHeight: 1 }}>{result.qri}</div>
                  </div>
                  <div style={{ padding: "16px 20px" }}>
                    <div className="label" style={{ marginBottom: 8 }}>REQUIRED NIST LEVEL</div>
                    <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-28)", fontWeight: 600, color: "var(--color-fg-0)", lineHeight: 1 }}>L{result.required_level.toFixed(2)}</div>
                  </div>
                </div>

                {/* Steps */}
                <div style={{ border: "1px solid var(--color-rule)", borderBottom: "none" }}>
                  <div style={{ padding: "8px 16px", borderBottom: "1px solid var(--color-rule)", background: "var(--color-ink-2)" }}>
                    <span className="label">DECISION WALKTHROUGH</span>
                  </div>
                  {result.step_by_step.map((step, i) => (
                    <div
                      key={i}
                      className="hover-surface"
                      style={{
                        display: "grid",
                        gridTemplateColumns: "36px 1fr",
                        gap: 16,
                        padding: "12px 16px",
                        borderBottom: "1px solid var(--color-rule-dim)",
                        transition: "background var(--fast) var(--ease)",
                      }}
                    >
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-11)", color: "var(--color-fg-2)", paddingTop: 2 }}>
                        {STEP_NUM[i] ?? `0${i + 1}`}
                      </span>
                      <span style={{ fontFamily: "var(--font-sans)", fontSize: "var(--text-13)", color: "var(--color-fg-1)", lineHeight: 1.6 }}>
                        {step}
                      </span>
                    </div>
                  ))}
                </div>

                {/* Final */}
                <div style={{ border: "1px solid var(--color-rule)", borderLeft: "2px solid var(--color-fg-0)", padding: "20px" }}>
                  <div className="label" style={{ marginBottom: 10 }}>FINAL SELECTION</div>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-16)", fontWeight: 700, color: "var(--color-fg-0)", marginBottom: 10 }}>
                    {result.selected}
                  </div>
                  <p style={{ fontFamily: "var(--font-sans)", fontSize: "var(--text-13)", color: "var(--color-fg-1)", lineHeight: 1.6 }}>
                    {result.selected_reason}
                  </p>
                </div>

              </div>
            ) : (
              <div
                style={{
                  display: "flex", alignItems: "center", justifyContent: "center",
                  minHeight: 300, border: "1px solid var(--color-rule-dim)",
                }}
              >
                <span className="label">{loading ? "RUNNING 8-STEP ANALYSIS…" : "SELECT DEVICE → RUN /EXPLAIN"}</span>
              </div>
            )}
          </div>
        </div>
      </main>
    </>
  );
}
