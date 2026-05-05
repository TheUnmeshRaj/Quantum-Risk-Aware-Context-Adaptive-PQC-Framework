// app/(dashboard)/algorithms/page.tsx
import { Topbar } from "@/components/layout/Topbar";

const ALGORITHMS = [
  {
    key: "kyber512_constrained",
    label: "Kyber-512 + Dilithium-2",
    mode: "Constrained Device",
    family: "Lattice — Module-LWE",
    level: 1, latency: "ULTRA-LOW",
    ram_min_kb: 32, requires_fpu: false,
    sizes: { "KEM PK": 800, "KEM CT": 768, "SIG PK": 1312, "SIG": 2420 },
    use_case: "IoT sensors, microcontrollers, embedded systems < 1 MB RAM.",
  },
  {
    key: "hybrid_kyber512",
    label: "Hybrid RSA-2048 + Kyber-512",
    mode: "Hybrid Transitional",
    family: "RSA + Lattice",
    level: 1, latency: "LOW",
    ram_min_kb: 64, requires_fpu: false,
    sizes: { "KEM PK": 800, "RSA CT": 256, "KEM CT": 768 },
    use_case: "Transition deployments where legacy RSA compatibility is required.",
  },
  {
    key: "kyber768_dilithium3",
    label: "Kyber-768 + Dilithium-3",
    mode: "Pure PQC",
    family: "Lattice — Module-LWE",
    level: 3, latency: "LOW",
    ram_min_kb: 128, requires_fpu: false,
    sizes: { "KEM PK": 1184, "KEM CT": 1088, "SIG PK": 1952, "SIG": 3293 },
    use_case: "General-purpose workstations, APIs, servers. NIST recommended baseline.",
  },
  {
    key: "kyber768_falcon512",
    label: "Kyber-768 + FALCON-512",
    mode: "Compact Signature",
    family: "Lattice — Module-LWE + NTRU",
    level: 3, latency: "MEDIUM",
    ram_min_kb: 256, requires_fpu: true,
    sizes: { "KEM PK": 1184, "KEM CT": 1088, "SIG PK": 897, "SIG": 690 },
    use_case: "Bandwidth-constrained channels. FALCON sig = 690 B vs Dilithium 3,293 B.",
  },
  {
    key: "kyber1024_dilithium5",
    label: "Kyber-1024 + Dilithium-5",
    mode: "High Assurance",
    family: "Lattice — Module-LWE",
    level: 5, latency: "MEDIUM",
    ram_min_kb: 256, requires_fpu: false,
    sizes: { "KEM PK": 1568, "KEM CT": 1568, "SIG PK": 2592, "SIG": 4595 },
    use_case: "Critical infrastructure, financial systems, government. Full NIST L5.",
  },
  {
    key: "kyber1024_dilithium5_sphincs",
    label: "Kyber-1024 + Dilithium-5 + SPHINCS+",
    mode: "Maximum Assurance",
    family: "Lattice + Hash-Based",
    level: 5, latency: "HIGH",
    ram_min_kb: 512, requires_fpu: false,
    sizes: { "KEM PK": 1568, "KEM CT": 1568, "SIG PK": 2592, "SIG": 4595, "SPHINCS SIG": 29792 },
    use_case: "Classified data, healthcare (25yr+), nation-state adversaries. Dual-primitive security.",
  },
];

const LATENCY_COLOR: Record<string, string> = {
  "ULTRA-LOW": "var(--color-green)",
  "LOW":       "var(--color-green)",
  "MEDIUM":    "var(--color-yellow)",
  "HIGH":      "var(--color-orange)",
};

const LEVEL_COLOR: Record<number, string> = {
  1: "var(--color-fg-2)",
  3: "var(--color-yellow)",
  5: "var(--color-red)",
};

export default function AlgorithmsPage() {
  return (
    <>
      <Topbar title="Algorithms" sub="NIST FIPS 203 / 204 / 205 — full catalogue" />
      <main style={{ padding: 24, flex: 1 }}>
        <div style={{ maxWidth: 1100 }}>

          {/* Table header */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "2fr 80px 80px 80px 1fr",
              padding: "8px 16px",
              background: "var(--color-ink-2)",
              border: "1px solid var(--color-rule)",
              borderBottom: "none",
            }}
          >
            {["ALGORITHM", "LEVEL", "LATENCY", "MIN RAM", "USE CASE"].map((h) => (
              <span key={h} className="label">{h}</span>
            ))}
          </div>

          {/* Rows */}
          <div style={{ border: "1px solid var(--color-rule)" }}>
            {ALGORITHMS.map((a) => (
              <div
                key={a.key}
                style={{
                  display: "grid",
                  gridTemplateColumns: "2fr 80px 80px 80px 1fr",
                  borderBottom: "1px solid var(--color-rule-dim)",
                }}
              >
                {/* Identity */}
                <div
                  style={{
                    padding: "16px",
                    borderRight: "1px solid var(--color-rule-dim)",
                  }}
                >
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
                  <div className="label" style={{ color: "var(--color-fg-2)", marginBottom: 4 }}>{a.key}</div>
                  <div
                    style={{
                      display: "inline-block",
                      padding: "2px 8px",
                      border: "1px solid var(--color-rule)",
                      fontFamily: "var(--font-mono)",
                      fontSize: "var(--text-10)",
                      letterSpacing: "0.06em",
                      color: "var(--color-fg-2)",
                    }}
                  >
                    {a.family}
                  </div>
                  {a.requires_fpu && (
                    <div
                      style={{
                        display: "inline-block",
                        marginLeft: 6,
                        padding: "2px 8px",
                        border: `1px solid var(--color-yellow)`,
                        fontFamily: "var(--font-mono)",
                        fontSize: "var(--text-10)",
                        letterSpacing: "0.06em",
                        color: "var(--color-yellow)",
                      }}
                    >
                      FPU
                    </div>
                  )}
                </div>

                {/* Level */}
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    padding: "16px",
                    borderRight: "1px solid var(--color-rule-dim)",
                  }}
                >
                  <span
                    style={{
                      fontFamily: "var(--font-mono)",
                      fontSize: "var(--text-16)",
                      fontWeight: 700,
                      color: LEVEL_COLOR[a.level] ?? "var(--color-fg-0)",
                    }}
                  >
                    L{a.level}
                  </span>
                </div>

                {/* Latency */}
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    padding: "16px",
                    borderRight: "1px solid var(--color-rule-dim)",
                  }}
                >
                  <span
                    style={{
                      fontFamily: "var(--font-mono)",
                      fontSize: "var(--text-11)",
                      letterSpacing: "0.04em",
                      color: LATENCY_COLOR[a.latency] ?? "var(--color-fg-1)",
                    }}
                  >
                    {a.latency}
                  </span>
                </div>

                {/* RAM */}
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    padding: "16px",
                    borderRight: "1px solid var(--color-rule-dim)",
                  }}
                >
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-12)", color: "var(--color-fg-1)" }}>
                    {a.ram_min_kb} KB
                  </span>
                </div>

                {/* Use case + key sizes */}
                <div style={{ padding: "16px" }}>
                  <p style={{ fontFamily: "var(--font-sans)", fontSize: "var(--text-12)", color: "var(--color-fg-1)", lineHeight: 1.6, marginBottom: 10 }}>
                    {a.use_case}
                  </p>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: "4px 16px" }}>
                    {Object.entries(a.sizes).map(([k, v]) => (
                      <span key={k} className="label">
                        {k} <span style={{ color: "var(--color-fg-1)", fontFamily: "var(--font-mono)", fontSize: "var(--text-10)" }}>{v.toLocaleString()} B</span>
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            ))}
          </div>

        </div>
      </main>
    </>
  );
}
