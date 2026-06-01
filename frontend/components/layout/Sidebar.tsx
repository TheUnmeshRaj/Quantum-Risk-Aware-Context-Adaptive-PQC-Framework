"use client";
// components/layout/Sidebar.tsx

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";
import { useMobileMenu } from "./DashboardShell";

const NAV = [
  { href: "/",           label: "Overview"   },
  { href: "/analyze",    label: "Analyze"    },
  { href: "/fleet",      label: "Fleet"      },
  { href: "/discover",   label: "Discover"   },
  { href: "/explain",    label: "Explain"    },
  { href: "/algorithms", label: "Algorithms" },
];

type SidebarProps = {
  collapsed?: boolean;
  onToggle?: () => void;
  isMobileDrawer?: boolean;
};

export function Sidebar({ collapsed: collapsedProp, onToggle, isMobileDrawer }: SidebarProps) {
  const path = usePathname();
  const [internalCollapsed, setInternalCollapsed] = useState(false);
  const { setMobileMenuOpen } = useMobileMenu();
  const isControlled = typeof collapsedProp === "boolean";
  const collapsed = isControlled ? collapsedProp! : internalCollapsed;
  const toggle = () => {
    if (isControlled) onToggle && onToggle();
    else setInternalCollapsed((c) => !c);
  };

  const handleNavClick = () => {
    setMobileMenuOpen(false);
  };

  return (
    <aside
      style={{
        width: collapsed ? 64 : 220,
        position: isMobileDrawer ? "absolute" : "fixed",
      }}
      className={`
        left-0 top-0 bottom-0 z-20
        surface-1 rule-r
        flex flex-col
        select-none
        transition-all duration-150 ease-in-out
      `}
    >
      {/* Identity */}
      <div className={`px-4 ${collapsed ? 'py-3' : 'py-5'} rule-b flex items-center`}>
        <div style={{ flex: 1 }}>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-14)", fontWeight: 700, letterSpacing: "0.08em", color: "var(--color-fg-0)" }} className="text-center w-full">
            {collapsed ? 'U' : 'UNYSIS'}
          </div>
        </div>
        <button
          onClick={toggle}
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          className="label t-12 text-fg-1"
          style={{ background: 'transparent', border: 'none', cursor: 'pointer', padding: 4 }}
        >
          {collapsed ? '»' : '‹'}
        </button>
      </div>

      {/* Nav */}
      <nav className="flex-1 py-3">
        {NAV.map(({ href, label }) => {
          const active = path === href || (href !== "/" && path.startsWith(href));
          return (
            <Link
              key={href}
              href={href}
              onClick={handleNavClick}
              className={`
                block px-4 py-2
                t-12 transition-colors
                focus-ring
                ${active
                  ? "text-fg-0 surface-2"
                  : "text-fg-2 hover-surface"
                }
              `}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                fontFamily: "var(--font-mono)",
                fontSize: "var(--text-14)",
                color: active ? "var(--color-fg-0)" : "var(--color-fg-2)",
                borderLeft: active ? "2px solid var(--color-fg-0)" : "2px solid transparent",
                paddingLeft: collapsed ? 12 : (active ? 18 : 20),
                paddingTop: collapsed ? 10 : 8,
                paddingBottom: collapsed ? 10 : 8,
              }}
            >
              <span style={{ width: collapsed ? 28 : 'auto', textAlign: collapsed ? 'center' : 'left', display: 'inline-flex', justifyContent: collapsed ? 'center' : 'flex-start' }}>
                {collapsed ? (
                  // Icon when collapsed
                  (function IconFor(l: string){
                    switch(l){
                      case 'Overview': return (
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden>
                          <path d="M3 11L12 3l9 8v8a1 1 0 0 1-1 1h-5v-6H9v6H4a1 1 0 0 1-1-1v-8z" fill="currentColor" />
                        </svg>
                      );
                      case 'Analyze': return (
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden>
                          <path d="M21 21l-4.35-4.35" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                          <circle cx="11" cy="11" r="6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                        </svg>
                      );
                      case 'Fleet': return (
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden>
                          <path d="M17 20v-2a4 4 0 0 0-4-4H7a4 4 0 0 0-4 4v2" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                          <circle cx="9" cy="7" r="4" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                        </svg>
                      );
                      case 'Discover': return (
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden>
                          <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="2" />
                          <circle cx="12" cy="12" r="5" stroke="currentColor" strokeWidth="2" />
                          <circle cx="12" cy="12" r="1" fill="currentColor" />
                          <path d="M12 2v20M2 12h20" stroke="currentColor" strokeWidth="1.5" strokeDasharray="3 3" />
                        </svg>
                      );
                      case 'Explain': return (
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden>
                          <path d="M9 18h6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                          <path d="M12 2a7 7 0 0 0-4 12" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                        </svg>
                      );
                      case 'Algorithms': return (
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden>
                          <path d="M20.24 12.24a6 6 0 1 0-8.48 8.48" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                          <path d="M7.76 11.76A6 6 0 1 0 16.24 3.28" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                        </svg>
                      );
                      default: return label.charAt(0);
                    }
                  })(label)
                ) : (
                  label
                )}
              </span>
            </Link>
          );
        })}
      </nav>

      {/* Version */}
      {!collapsed && (
        <div className="px-4 py-3 rule-t">
          <div className="label">v2.0.0</div>
          <div className="label mt-1" style={{ color: "var(--color-fg-3)" }}>NIST FIPS 203/204/205</div>
        </div>
      )}
    </aside>
  );
}
