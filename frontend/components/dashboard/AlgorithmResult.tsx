// components/dashboard/AlgorithmResult.tsx
import type { AnalyzeResponse } from "@/lib/types";
import { TierTag, tierColor } from "@/components/ui/TierTag";
import { LabelledBar, Bar } from "@/components/ui/Bar";

export function AlgorithmResult({ data }: { data: AnalyzeResponse }) {
  const gap = data.security_gap > 0;
  const compliance = data.achieved_nist_level / 5;

  return (
    <div className="fade-in" style={{ display: "flex", flexDirection: "column" }}>

      {/* ── Primary output ── */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr 1fr",
          borderBottom: "1px solid var(--color-rule)",
        }}
      >
        <div style={{ padding: "20px", borderRight: "1px solid var(--color-rule)" }}>
          <div className="label" style={{ marginBottom: 10 }}>SELECTED ALGORITHM</div>
          <div
            style={{
              fontFamily: "var(--font-mono)",
              fontSize: "var(--text-14)",
              fontWeight: 600,
              color: "var(--color-fg-0)",
              lineHeight: 1.3,
              marginBottom: 6,
            }}
          >
            {data.selected_algorithm}
          </div>
          <div className="label" style={{ color: "var(--color-fg-2)" }}>
            {data.mode} · {data.security_level}
          </div>
        </div>

        <div style={{ padding: "20px", borderRight: "1px solid var(--color-rule)" }}>
          <div className="label" style={{ marginBottom: 10 }}>QUANTUM RISK INDEX</div>
          <div
            style={{
              fontFamily: "var(--font-mono)",
              fontSize: "var(--text-28)",
              fontWeight: 600,
              color: tierColor(data.qri_tier),
              lineHeight: 1,
              marginBottom: 8,
            }}
          >
            {data.qri}
          </div>
          <TierTag tier={data.qri_tier} />
        </div>

        <div style={{ padding: "20px" }}>
          <div className="label" style={{ marginBottom: 10 }}>NIST COMPLIANCE</div>
          <div
            style={{
              fontFamily: "var(--font-mono)",
              fontSize: "var(--text-28)",
              fontWeight: 600,
              color: gap ? "var(--color-yellow)" : "var(--color-fg-0)",
              lineHeight: 1,
              marginBottom: 8,
            }}
          >
            L{data.achieved_nist_level}
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            <Bar value={compliance} color={gap ? "var(--color-yellow)" : "var(--color-fg-0)"} height={2} />
            {gap && (
              <div className="label" style={{ color: "var(--color-yellow)" }}>
                GAP {data.security_gap.toFixed(2)} — REQUIRED L{data.required_nist_level}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ── Score breakdown ── */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          borderBottom: "1px solid var(--color-rule)",
        }}
      >
        <div style={{ padding: "20px", borderRight: "1px solid var(--color-rule)" }}>
          <div className="label" style={{ marginBottom: 14 }}>SCORE BREAKDOWN</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            <LabelledBar label="Security Fit"  value={data.breakdown.security_fit}  />
            <LabelledBar label="RAM Fit"        value={data.breakdown.ram_fit}        />
            <LabelledBar label="Bandwidth Fit"  value={data.breakdown.bandwidth_fit}  />
            <LabelledBar label="Final Score"    value={data.breakdown.final_score}  color="var(--color-fg-0)" />
          </div>
        </div>

        <div style={{ padding: "20px" }}>
          <div className="label" style={{ marginBottom: 14 }}>SELECTION REASON</div>
          <p
            style={{
              fontFamily: "var(--font-sans)",
              fontSize: "var(--text-13)",
              color: "var(--color-fg-1)",
              lineHeight: 1.6,
              borderLeft: "1px solid var(--color-rule)",
              paddingLeft: 12,
            }}
          >
            {data.reason}
          </p>
          <div style={{ marginTop: 16 }}>
            <div className="label" style={{ marginBottom: 8 }}>LATENCY</div>
            <span
              style={{
                fontFamily: "var(--font-mono)",
                fontSize: "var(--text-12)",
                color: "var(--color-fg-0)",
              }}
            >
              {data.processing_time_ms.toFixed(2)} ms
            </span>
          </div>
        </div>
      </div>

      {/* ── Alternatives ── */}
      {data.alternatives.length > 0 && (
        <div style={{ borderBottom: "1px solid var(--color-rule)" }}>
          <div style={{ padding: "10px 20px", borderBottom: "1px solid var(--color-rule-dim)" }}>
            <span className="label">ALTERNATIVES</span>
          </div>
          {data.alternatives.map((a) => (
            <div
              key={a.key}
              className="hover-surface"
              style={{
                display: "grid",
                gridTemplateColumns: "1fr auto auto",
                gap: 20,
                padding: "10px 20px",
                borderBottom: "1px solid var(--color-rule-dim)",
                alignItems: "center",
              }}
            >
              <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-12)", color: "var(--color-fg-1)" }}>{a.key}</span>
              <span className="label">NIST L{a.level}</span>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-12)", color: "var(--color-fg-2)", width: 60, textAlign: "right" }}>{a.score.toFixed(4)}</span>
            </div>
          ))}
        </div>
      )}

      {/* ── Rejected ── */}
      {data.rejected.length > 0 && (
        <details>
          <summary
            className="hover-surface"
            style={{
              padding: "10px 20px",
              cursor: "pointer",
              listStyle: "none",
              display: "flex",
              alignItems: "center",
              gap: 8,
              borderBottom: "1px solid var(--color-rule-dim)",
            }}
          >
            <span className="label" style={{ color: "var(--color-red)" }}>REJECTED ({data.rejected.length})</span>
          </summary>
          {data.rejected.map((r) => (
            <div
              key={r.algorithm}
              style={{
                display: "grid",
                gridTemplateColumns: "200px 1fr",
                gap: 16,
                padding: "10px 20px",
                borderBottom: "1px solid var(--color-rule-dim)",
                borderLeft: "2px solid var(--color-red)",
              }}
            >
              <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-12)", color: "var(--color-red)" }}>{r.algorithm}</span>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-12)", color: "var(--color-fg-2)" }}>{r.reason}</span>
            </div>
          ))}
        </details>
      )}
    </div>
  );
}
