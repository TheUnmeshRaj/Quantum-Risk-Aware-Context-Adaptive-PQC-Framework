"use client";
// app/(dashboard)/analyze/AnalyzeContent.tsx

import { useState } from "react";
import { api } from "@/lib/api";
import { useProfiles } from "@/context/ProfilesContext";
import { AlgorithmResult } from "@/components/dashboard/AlgorithmResult";
import { Stat } from "@/components/ui/Stat";
import type { AnalyzeResponse, DeviceProfileRequest } from "@/lib/types";

const ADVERSARY = ["low", "medium", "nation_state"] as const;

export function AnalyzeContent() {
  const { profiles, addProfile } = useProfiles();
  const [idx, setIdx] = useState(0);
  const [adversary, setAdversary] = useState<"low" | "medium" | "nation_state">("medium");
  const [result, setResult] = useState<AnalyzeResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Custom profile creation state
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [formName, setFormName] = useState("");
  const [formDesc, setFormDesc] = useState("");
  const [formSensitivity, setFormSensitivity] = useState(5.0);
  const [formExposure, setFormExposure] = useState(5.0);
  const [formLifetime, setFormLifetime] = useState(10);
  const [formThreatWindow, setFormThreatWindow] = useState(5.0);
  const [formAdversary, setFormAdversary] = useState<"low" | "medium" | "nation_state">("medium");
  const [formRam, setFormRam] = useState(1024);
  const [formCpu, setFormCpu] = useState("ARM Cortex-M4");
  const [formHasFpu, setFormHasFpu] = useState(false);
  const [formBandwidth, setFormBandwidth] = useState(100);

  const base = profiles[idx] || profiles[0];
  const payload: DeviceProfileRequest = base ? {
    ...base,
    adversary,
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
    try { setResult(await api.analyze(payload)); }
    catch (e: unknown) { setError(e instanceof Error ? e.message : "error"); }
    finally { setLoading(false); }
  }

  const handleSaveCustomProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formName.trim()) {
      setError("Profile name is required.");
      return;
    }

    const newProfile: DeviceProfileRequest = {
      name: formName.trim(),
      description: formDesc.trim() || undefined,
      data_sensitivity: Number(formSensitivity),
      exposure_level: Number(formExposure),
      data_lifetime_yrs: Number(formLifetime),
      threat_window: Number(formThreatWindow),
      adversary: formAdversary,
      hardware: {
        ram_kb: Number(formRam),
        cpu: formCpu.trim() || "Unknown CPU",
        has_fpu: Boolean(formHasFpu),
        bandwidth_kbps: Number(formBandwidth),
      }
    };

    addProfile(newProfile);

    // Find index of the newly added profile (which gets appended to profiles)
    // and select it
    const newIndex = profiles.length;
    setIdx(newIndex);
    setShowCreateForm(false);
    setResult(null);

    // Reset form fields
    setFormName("");
    setFormDesc("");
    setFormSensitivity(5.0);
    setFormExposure(5.0);
    setFormLifetime(10);
    setFormThreatWindow(5.0);
    setFormAdversary("medium");
    setFormRam(1024);
    setFormCpu("ARM Cortex-M4");
    setFormHasFpu(false);
    setFormBandwidth(100);

    // Run analysis immediately on the new profile
    setLoading(true);
    setError(null);
    try {
      const activePayload = {
        ...newProfile,
        hardware: { ...newProfile.hardware, ram_kb: Math.min(newProfile.hardware.ram_kb, 2_000_000) }
      };
      setResult(await api.analyze(activePayload));
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "error running auto-analysis");
    } finally {
      setLoading(false);
    }
  };

  const S: React.CSSProperties = {
    fontFamily: "var(--font-mono)",
    fontSize: "var(--text-12)",
    color: "var(--color-fg-1)",
  };

  const inputStyle: React.CSSProperties = {
    background: "var(--color-ink-2)",
    color: "var(--color-fg-0)",
    border: "1px solid var(--color-rule-dim)",
    padding: "8px 12px",
    fontFamily: "var(--font-mono)",
    fontSize: "var(--text-12)",
    width: "100%",
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
          <div className="label" style={{ marginBottom: 8, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span>DEVICE PROFILE</span>
            <button
              onClick={() => {
                setShowCreateForm(true);
                setResult(null);
              }}
              style={{
                background: "transparent",
                border: "none",
                color: "var(--color-fg-0)",
                fontSize: "var(--text-10)",
                fontFamily: "var(--font-mono)",
                cursor: "pointer",
                padding: "2px 6px",
                borderBottom: "1px dashed var(--color-fg-2)"
              }}
            >
              + ADD NEW
            </button>
          </div>
          <select
            value={idx}
            onChange={(e) => {
              setIdx(Number(e.target.value));
              setResult(null);
              setShowCreateForm(false);
            }}
            style={{ ...S, width: "100%", padding: "8px 10px", cursor: "pointer", background: "var(--color-ink-2)", border: "1px solid var(--color-rule)" }}
          >
            {profiles.map((d, i) => <option key={i} value={i}>{d.name}</option>)}
          </select>
        </div>

        {/* Adversary */}
        <div>
          <div className="label" style={{ marginBottom: 8 }}>ADVERSARY MODEL</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
            {ADVERSARY.map((a) => (
              <button
                key={a}
                onClick={() => {
                  setAdversary(a);
                  setResult(null);
                  setShowCreateForm(false);
                }}
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
        {!showCreateForm && base && (
          <div style={{ borderTop: "1px solid var(--color-rule-dim)", paddingTop: 16 }}>
            <div className="label" style={{ marginBottom: 10 }}>PARAMETERS</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              {[
                ["SENSITIVITY", base.data_sensitivity],
                ["EXPOSURE", base.exposure_level],
                ["LIFETIME", `${base.data_lifetime_yrs}yr`],
                ["THREAT WIN", base.threat_window],
                ["RAM", `${(Math.min(base.hardware.ram_kb, 2_000_000) / 1024).toFixed(0)} MB`],
              ].map(([k, v]) => (
                <div key={String(k)} style={{ display: "flex", justifyContent: "space-between" }}>
                  <span className="label">{k}</span>
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-11)", color: "var(--color-fg-1)" }}>{v}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Run */}
        {!showCreateForm && (
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <button
              onClick={run}
              disabled={loading}
              style={{
                padding: "10px",
                fontFamily: "var(--font-mono)",
                fontSize: "var(--text-12)",
                fontWeight: 700,
                letterSpacing: "0.08em",
                textTransform: "uppercase",
                background: loading ? "var(--color-ink-2)" : "var(--color-fg-0)",
                color: loading ? "var(--color-fg-2)" : "var(--color-ink-0)",
                border: "none",
                cursor: loading ? "not-allowed" : "pointer",
                transition: "all var(--fast) var(--ease)",
              }}
            >
              {loading ? "ANALYZING…" : "RUN /ANALYZE"}
            </button>
            <button
              onClick={() => {
                setIdx(0);
                setAdversary("medium");
                setResult(null);
                setError(null);
              }}
              style={{
                padding: "10px",
                fontFamily: "var(--font-mono)",
                fontSize: "var(--text-12)",
                fontWeight: 700,
                letterSpacing: "0.08em",
                textTransform: "uppercase",
                background: "transparent",
                color: "var(--color-fg-2)",
                border: "1px solid var(--color-rule)",
                cursor: "pointer",
                transition: "all var(--fast) var(--ease)",
              }}
            >
              RESET
            </button>
          </div>
        )}

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

      {/* ── Result / Form Panel ── */}
      <div style={{ paddingLeft: 24 }}>
        {showCreateForm ? (
          <div className="fade-in" style={{ border: "1px solid var(--color-rule)", padding: 24, background: "var(--color-ink-3)" }}>
            <div style={{ borderBottom: "1px solid var(--color-rule)", paddingBottom: 12, marginBottom: 20 }}>
              <h2 style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-16)", fontWeight: 700, color: "var(--color-fg-0)" }}>
                CREATE CUSTOM DEVICE PROFILE
              </h2>
              <p style={{ fontFamily: "var(--font-sans)", fontSize: "var(--text-12)", color: "var(--color-fg-2)", marginTop: 4 }}>
                Fill in the data parameters and hardware characteristics to simulate custom risk.
              </p>
            </div>

            <form onSubmit={handleSaveCustomProfile} style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              {/* Profile Details */}
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
                <div>
                  <label className="label" style={{ marginBottom: 6, display: "block" }}>PROFILE NAME</label>
                  <input
                    type="text"
                    value={formName}
                    onChange={(e) => setFormName(e.target.value)}
                    placeholder="e.g. Edge Camera Controller"
                    required
                    style={inputStyle}
                  />
                </div>
                <div>
                  <label className="label" style={{ marginBottom: 6, display: "block" }}>DESCRIPTION</label>
                  <input
                    type="text"
                    value={formDesc}
                    onChange={(e) => setFormDesc(e.target.value)}
                    placeholder="e.g. Low-power outdoor surveillance node"
                    style={inputStyle}
                  />
                </div>
              </div>

              <div style={{ borderBottom: "1px solid var(--color-rule-dim)", margin: "8px 0" }} />

              {/* Risk metrics */}
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
                <div>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                    <label className="label">DATA SENSITIVITY (0-10)</label>
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-12)", color: "var(--color-fg-0)" }}>{formSensitivity.toFixed(1)}</span>
                  </div>
                  <input
                    type="range"
                    min="0"
                    max="10"
                    step="0.1"
                    value={formSensitivity}
                    onChange={(e) => setFormSensitivity(Number(e.target.value))}
                    style={{ width: "100%", accentColor: "var(--color-fg-0)" }}
                  />
                </div>
                <div>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                    <label className="label">EXPOSURE LEVEL (0-10)</label>
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-12)", color: "var(--color-fg-0)" }}>{formExposure.toFixed(1)}</span>
                  </div>
                  <input
                    type="range"
                    min="0"
                    max="10"
                    step="0.1"
                    value={formExposure}
                    onChange={(e) => setFormExposure(Number(e.target.value))}
                    style={{ width: "100%", accentColor: "var(--color-fg-0)" }}
                  />
                </div>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
                <div>
                  <label className="label" style={{ marginBottom: 6, display: "block" }}>DATA LIFETIME (YEARS)</label>
                  <input
                    type="number"
                    min="0"
                    max="100"
                    value={formLifetime}
                    onChange={(e) => setFormLifetime(Number(e.target.value))}
                    style={inputStyle}
                  />
                </div>
                <div>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                    <label className="label">THREAT WINDOW (0-10)</label>
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-12)", color: "var(--color-fg-0)" }}>{formThreatWindow.toFixed(1)}</span>
                  </div>
                  <input
                    type="range"
                    min="0"
                    max="10"
                    step="0.1"
                    value={formThreatWindow}
                    onChange={(e) => setFormThreatWindow(Number(e.target.value))}
                    style={{ width: "100%", accentColor: "var(--color-fg-0)" }}
                  />
                </div>
              </div>

              <div style={{ borderBottom: "1px solid var(--color-rule-dim)", margin: "8px 0" }} />

              {/* Hardware */}
              <div>
                <span className="label" style={{ color: "var(--color-fg-0)", marginBottom: 12, display: "block" }}>HARDWARE SPECS</span>

                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
                  <div>
                    <label className="label" style={{ marginBottom: 6, display: "block" }}>RAM (KB)</label>
                    <input
                      type="number"
                      min="1"
                      value={formRam}
                      onChange={(e) => setFormRam(Number(e.target.value))}
                      style={inputStyle}
                    />
                  </div>
                  <div>
                    <label className="label" style={{ marginBottom: 6, display: "block" }}>CPU FAMILY</label>
                    <input
                      type="text"
                      value={formCpu}
                      onChange={(e) => setFormCpu(e.target.value)}
                      placeholder="e.g. ARM Cortex-M4"
                      style={inputStyle}
                    />
                  </div>
                </div>

                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginTop: 12 }}>
                  <div>
                    <label className="label" style={{ marginBottom: 6, display: "block" }}>BANDWIDTH (KBPS)</label>
                    <input
                      type="number"
                      min="1"
                      value={formBandwidth}
                      onChange={(e) => setFormBandwidth(Number(e.target.value))}
                      style={inputStyle}
                    />
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: 10, height: "100%", paddingTop: 20 }}>
                    <div
                      onClick={() => setFormHasFpu(!formHasFpu)}
                      style={{
                        width: 18,
                        height: 18,
                        background: formHasFpu ? "#ffffff" : "var(--color-ink-1)",
                        border: "1px solid var(--color-rule)",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        cursor: "pointer",
                        userSelect: "none",
                        transition: "all var(--fast) var(--ease)",
                      }}
                    >
                      {formHasFpu && (
                        <span style={{ color: "#000000", fontSize: "12px", fontWeight: "bold", lineHeight: 1 }}>
                          ✓
                        </span>
                      )}
                    </div>
                    <span
                      onClick={() => setFormHasFpu(!formHasFpu)}
                      className="label"
                      style={{ userSelect: "none", cursor: "pointer" }}
                    >
                      HAS HARDWARE FPU
                    </span>
                  </div>
                </div>
              </div>

              {/* Adversary group */}
              <div>
                <label className="label" style={{ marginBottom: 6, display: "block" }}>ADVERSARY THREAT SCENARIO</label>
                <div style={{ display: "flex", gap: 10 }}>
                  {ADVERSARY.map((a) => (
                    <button
                      key={a}
                      type="button"
                      onClick={() => setFormAdversary(a)}
                      style={{
                        ...S,
                        flex: 1,
                        padding: "10px",
                        background: formAdversary === a ? "var(--color-fg-0)" : "var(--color-ink-2)",
                        color: formAdversary === a ? "var(--color-ink-0)" : "var(--color-fg-2)",
                        border: "1px solid var(--color-rule-dim)",
                        fontWeight: formAdversary === a ? 700 : 400,
                        cursor: "pointer",
                        textTransform: "uppercase",
                      }}
                    >
                      {a}
                    </button>
                  ))}
                </div>
              </div>

              {/* Form Actions */}
              <div style={{ display: "flex", gap: 16, marginTop: 12 }}>
                <button
                  type="submit"
                  style={{
                    flex: 1,
                    padding: "12px",
                    fontFamily: "var(--font-mono)",
                    fontSize: "var(--text-12)",
                    fontWeight: 700,
                    textTransform: "uppercase",
                    background: "var(--color-fg-0)",
                    color: "var(--color-ink-0)",
                    border: "none",
                    cursor: "pointer",
                  }}
                >
                  SAVE & ANALYZE PROFILE
                </button>
                <button
                  type="button"
                  onClick={() => setShowCreateForm(false)}
                  style={{
                    padding: "12px 24px",
                    fontFamily: "var(--font-mono)",
                    fontSize: "var(--text-12)",
                    textTransform: "uppercase",
                    background: "transparent",
                    color: "var(--color-fg-2)",
                    border: "1px solid var(--color-rule)",
                    cursor: "pointer",
                  }}
                >
                  CANCEL
                </button>
              </div>
            </form>
          </div>
        ) : result ? (
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
              <Stat label="QRI Score" value={result.qri} sub={result.qri_tier} ruled />
              <Stat label="Required L" value={`L${result.required_nist_level}`} />
              <Stat label="Process Time" value={`${result.processing_time_ms.toFixed(2)}ms`} />
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

