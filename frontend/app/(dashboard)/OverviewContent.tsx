"use client";
// app/(dashboard)/OverviewContent.tsx

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { DEVICE_PROFILES } from "@/lib/fixtures";
import { Stat } from "@/components/ui/Stat";
import { Skel } from "@/components/ui/Skeleton";
import { TierTag, tierColor } from "@/components/ui/TierTag";
import { Bar } from "@/components/ui/Bar";
import type { FleetMetrics, HealthResponse, AnalyzeResponse } from "@/lib/types";

const ALGO_CATALOGUE = [
  { key: "kyber512_constrained",         label: "Kyber-512 + Dilithium-2",             level: 1, family: "Lattice" },
  { key: "hybrid_kyber512",              label: "Hybrid RSA-2048 + Kyber-512",          level: 1, family: "Hybrid" },
  { key: "kyber768_dilithium3",          label: "Kyber-768 + Dilithium-3",              level: 3, family: "Lattice" },
  { key: "kyber768_falcon512",           label: "Kyber-768 + FALCON-512",               level: 3, family: "Lattice" },
  { key: "kyber1024_dilithium5",         label: "Kyber-1024 + Dilithium-5",             level: 5, family: "Lattice" },
  { key: "kyber1024_dilithium5_sphincs", label: "Kyber-1024 + Dilithium-5 + SPHINCS+", level: 5, family: "Hash"    },
];

export function OverviewContent() {
  const [health,  setHealth]  = useState<HealthResponse | null>(null);
  const [fleet,   setFleet]   = useState<{ metrics: FleetMetrics; results: AnalyzeResponse[] } | null>(null);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState<string | null>(null);

  useEffect(() => {
    Promise.all([api.health(), api.simulate(DEVICE_PROFILES)])
      .then(([h, sim]) => {
        setHealth(h);
        setFleet({ metrics: sim.fleet_metrics, results: sim.results });
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div style={{ display: "flex", flexDirection: "column", maxWidth: 1200 }}>

      {/* ── API Status ── */}
      <section style={{ borderBottom: "1px solid var(--color-rule)", paddingBottom: 24, marginBottom: 24 }}>
        <div className="label" style={{ marginBottom: 12 }}>API STATUS</div>
        {health ? (
          <div
            className="fade-in"
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(4, auto)",
              gap: 0,
              border: "1px solid var(--color-rule)",
              width: "fit-content",
            }}
          >
            {[
              ["SERVICE",  health.service],
              ["VERSION",  `v${health.version}`],
              ["UPTIME",   `${Math.floor(health.uptime_sec)}s`],
              ["STATUS",   "HEALTHY"],
            ].map(([label, val], i) => (
              <div
                key={label}
                style={{
                  padding: "10px 20px",
                  borderRight: i < 3 ? "1px solid var(--color-rule)" : undefined,
                }}
              >
                <div className="label" style={{ marginBottom: 4 }}>{label}</div>
                <div
                  style={{
                    fontFamily: "var(--font-mono)",
                    fontSize: "var(--text-13)",
                    fontWeight: 600,
                    color: label === "STATUS" ? "var(--color-green)" : "var(--color-fg-0)",
                  }}
                >
                  {val}
                </div>
              </div>
            ))}
          </div>
        ) : error ? (
          <div
            style={{
              padding: "10px 16px",
              border: "1px solid var(--color-rule)",
              borderLeft: "2px solid var(--color-red)",
            }}
          >
            <span
              style={{
                fontFamily: "var(--font-mono)",
                fontSize: "var(--text-12)",
                color: "var(--color-red)",
              }}
            >
              OFFLINE — run: uvicorn backend.api.app:app --port 8000
            </span>
          </div>
        ) : (
          <div style={{ display: "flex", gap: 12 }}>
            {[120, 80, 60, 100].map((w, i) => <Skel key={i} w={w} h={40} />)}
          </div>
        )}
      </section>

      {/* ── Fleet KPIs ── */}
      <section style={{ borderBottom: "1px solid var(--color-rule)", paddingBottom: 24, marginBottom: 24 }}>
        <div className="label" style={{ marginBottom: 12 }}>FLEET METRICS</div>
        {loading ? (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", border: "1px solid var(--color-rule)" }}>
            {Array.from({ length: 4 }).map((_, i) => (
              <div key={i} style={{ padding: 20, borderRight: i < 3 ? "1px solid var(--color-rule)" : undefined }}>
                <Skel h={10} w={60} />
                <div style={{ marginTop: 12 }}><Skel h={24} w={80} /></div>
              </div>
            ))}
          </div>
        ) : fleet ? (
          <div
            className="fade-in"
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(4, 1fr)",
              border: "1px solid var(--color-rule)",
            }}
          >
            <Stat label="Devices"    value={fleet.metrics.device_count}           ruled />
            <Stat label="Avg QRI"    value={fleet.metrics.avg_qri}                sub={`max ${fleet.metrics.max_qri}`} />
            <Stat label="Critical"   value={fleet.metrics.critical_count}         sub={`${fleet.metrics.high_count} HIGH`} color={fleet.metrics.critical_count > 0 ? "var(--color-red)" : undefined} />
            <Stat label="Compliance" value={`${fleet.metrics.avg_compliance_score}%`} />
          </div>
        ) : null}
      </section>

      {/* ── Fleet table ── */}
      {fleet && (
        <section style={{ borderBottom: "1px solid var(--color-rule)", paddingBottom: 24, marginBottom: 24 }}>
          <div className="label" style={{ marginBottom: 12 }}>DEVICE ASSIGNMENTS</div>
          <div
            className="fade-in"
            style={{ border: "1px solid var(--color-rule)" }}
          >
            {/* Header */}
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "2fr 80px 2fr 60px 60px 80px",
                gap: 0,
                padding: "8px 16px",
                borderBottom: "1px solid var(--color-rule)",
                background: "var(--color-ink-2)",
              }}
            >
              {["DEVICE", "QRI", "ALGORITHM", "LEVEL", "NIST%", "TIME"].map((h) => (
                <span key={h} className="label">{h}</span>
              ))}
            </div>

            {fleet.results.map((r) => (
              <div
                key={r.device}
                className="hover-surface"
                style={{
                  display: "grid",
                  gridTemplateColumns: "2fr 80px 2fr 60px 60px 80px",
                  gap: 0,
                  padding: "12px 16px",
                  borderBottom: "1px solid var(--color-rule-dim)",
                  borderLeft: `2px solid ${tierColor(r.qri_tier)}`,
                  alignItems: "center",
                  transition: "background var(--fast) var(--ease)",
                }}
              >
                <div>
                  <div
                    style={{
                      fontFamily: "var(--font-sans)",
                      fontSize: "var(--text-13)",
                      fontWeight: 500,
                      color: "var(--color-fg-0)",
                    }}
                  >
                    {r.device}
                  </div>
                  <TierTag tier={r.qri_tier} />
                </div>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-14)", fontWeight: 600, color: tierColor(r.qri_tier) }}>{r.qri}</span>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-11)", color: "var(--color-fg-1)" }}>{r.selected_algorithm}</span>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-13)", color: "var(--color-fg-0)" }}>L{r.achieved_nist_level}</span>
                <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
                  <span className="label">{Math.round((r.achieved_nist_level / 5) * 100)}%</span>
                  <Bar value={r.achieved_nist_level / 5} height={2} />
                </div>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-11)", color: "var(--color-fg-2)", textAlign: "right" }}>{r.processing_time_ms.toFixed(1)}ms</span>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* ── Algorithm catalogue ── */}
      <section>
        <div className="label" style={{ marginBottom: 12 }}>ALGORITHM CATALOGUE</div>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(3, 1fr)",
            border: "1px solid var(--color-rule)",
          }}
        >
          {ALGO_CATALOGUE.map((a, i) => (
            <div
              key={a.key}
              className="hover-surface"
              style={{
                padding: 16,
                borderRight: (i + 1) % 3 !== 0 ? "1px solid var(--color-rule)" : undefined,
                borderBottom: i < 3 ? "1px solid var(--color-rule)" : undefined,
                cursor: "default",
                transition: "background var(--fast) var(--ease)",
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
                <span className="label" style={{ color: "var(--color-fg-1)" }}>{a.family}</span>
                <span className="label">L{a.level}</span>
              </div>
              <div
                style={{
                  fontFamily: "var(--font-mono)",
                  fontSize: "var(--text-13)",
                  fontWeight: 600,
                  color: "var(--color-fg-0)",
                  marginBottom: 4,
                }}
              >
                {a.label}
              </div>
              <div className="label" style={{ color: "var(--color-fg-2)" }}>{a.key}</div>
            </div>
          ))}
        </div>
      </section>

    </div>
  );
}
