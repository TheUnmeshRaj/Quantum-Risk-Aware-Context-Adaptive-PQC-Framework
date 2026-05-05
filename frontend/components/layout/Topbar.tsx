"use client";
// components/layout/Topbar.tsx

import { useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import { api } from "@/lib/api";
import { useMobileMenu } from "./DashboardShell";
import type { HealthResponse } from "@/lib/types";

export function Topbar({ title, sub }: { title: string; sub?: string }) {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [err, setErr] = useState(false);
  const { mobileMenuOpen, setMobileMenuOpen } = useMobileMenu();

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
        {/* Mobile menu button */}
        <button
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          className="md:hidden"
          style={{
            background: "transparent",
            border: "none",
            color: "var(--color-fg-0)",
            cursor: "pointer",
            padding: "4px 8px",
            marginRight: "8px",
          }}
          aria-label="Toggle menu"
        >
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <line x1="3" y1="6" x2="21" y2="6"></line>
            <line x1="3" y1="12" x2="21" y2="12"></line>
            <line x1="3" y1="18" x2="21" y2="18"></line>
          </svg>
        </button>

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
            <span className="label hidden sm:inline" style={{ color: "var(--color-fg-2)" }}>
              {sub}
            </span>
          )}
        </div>

        {/* Status cluster */}
        <div className="flex items-center gap-2 sm:gap-5">
          {health ? (
            <>
              <span className="label hidden sm:inline" style={{ color: "var(--color-green)" }}>
                <span className="blink" style={{ display: "inline-block", width: 5, height: 5, background: "var(--color-green)", borderRadius: "50%", marginRight: 5, verticalAlign: "middle" }} />
                ONLINE
              </span>
              <span className="label hidden sm:inline">{Math.floor(health.uptime_sec)}s uptime</span>
            </>
          ) : err ? (
            <span className="label c-red hidden sm:inline">OFFLINE</span>
          ) : (
            <span className="label hidden sm:inline">CONNECTING</span>
          )}

          <a
            href="/docs.pdf"
            target="_blank"
            rel="noopener"
            className="focus-ring hidden sm:inline-block"
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
