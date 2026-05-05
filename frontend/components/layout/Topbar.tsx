"use client";
// components/layout/Topbar.tsx

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { HealthResponse } from "@/lib/types";

export function Topbar({ title, sub }: { title: string; sub?: string }) {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [err, setErr] = useState(false);

  useEffect(() => {
    api.health().then(setHealth).catch(() => setErr(true));
  }, []);

  return (
    <header
      className="sticky top-0 z-10 surface-0 rule-b"
      style={{ height: 40 }}
    >
      <div
        className="flex items-center justify-between h-full"
        style={{ paddingLeft: 20, paddingRight: 20 }}
      >
        {/* Title */}
        <div className="flex items-baseline gap-3">
          <span
            style={{
              fontFamily: "var(--font-mono)",
              fontSize: "var(--text-13)",
              fontWeight: 600,
              color: "var(--color-fg-0)",
              letterSpacing: "0.03em",
            }}
          >
            {title}
          </span>
          {sub && (
            <span className="label" style={{ color: "var(--color-fg-2)" }}>
              {sub}
            </span>
          )}
        </div>

        {/* Status cluster */}
        <div className="flex items-center gap-5">
          {health ? (
            <>
              <span className="label" style={{ color: "var(--color-green)" }}>
                <span className="blink" style={{ display: "inline-block", width: 5, height: 5, background: "var(--color-green)", borderRadius: "50%", marginRight: 5, verticalAlign: "middle" }} />
                ONLINE
              </span>
              <span className="label">{Math.floor(health.uptime_sec)}s uptime</span>
            </>
          ) : err ? (
            <span className="label c-red">OFFLINE</span>
          ) : (
            <span className="label">CONNECTING</span>
          )}

          <a
            href="http://localhost:8000/docs"
            target="_blank"
            rel="noopener"
            className="focus-ring"
            style={{
              fontFamily: "var(--font-mono)",
              fontSize: "var(--text-10)",
              letterSpacing: "0.08em",
              textTransform: "uppercase",
              color: "var(--color-fg-2)",
              textDecoration: "none",
              borderBottom: "1px solid var(--color-fg-2)",
              paddingBottom: 1,
              transition: "color var(--fast) var(--ease)",
            }}
            onMouseEnter={(e) => (e.currentTarget.style.color = "var(--color-fg-0)")}
            onMouseLeave={(e) => (e.currentTarget.style.color = "var(--color-fg-2)")}
          >
            API DOCS
          </a>
        </div>
      </div>
    </header>
  );
}
