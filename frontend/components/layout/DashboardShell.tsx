"use client";
import { useState, useEffect, createContext, useContext } from "react";
import { Sidebar } from "./Sidebar";
import { Topbar } from "./Topbar";

type MobileMenuContextType = {
  mobileMenuOpen: boolean;
  setMobileMenuOpen: (open: boolean) => void;
};

const MobileMenuContext = createContext<MobileMenuContextType | undefined>(undefined);

export function useMobileMenu() {
  const ctx = useContext(MobileMenuContext);
  if (!ctx) throw new Error("useMobileMenu must be used inside DashboardShell");
  return ctx;
}

export default function DashboardShell({ children }: { children: React.ReactNode }) {
  const [collapsed, setCollapsed] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [isMobile, setIsMobile] = useState(false);

  useEffect(() => {
    const handleResize = () => setIsMobile(window.innerWidth < 768);
    handleResize();
    window.addEventListener("resize", handleResize);
    return () => window.removeEventListener("resize", handleResize);
  }, []);

  const marginLeft = isMobile ? 0 : (collapsed ? 64 : 220);

  return (
    <MobileMenuContext.Provider value={{ mobileMenuOpen, setMobileMenuOpen }}>
      <div className="min-h-dvh flex flex-col">
        {/* Desktop sidebar */}
        {!isMobile && (
          <Sidebar collapsed={collapsed} onToggle={() => setCollapsed((c) => !c)} />
        )}

        {/* Mobile overlay */}
        {isMobile && mobileMenuOpen && (
          <div
            style={{
              position: "fixed",
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              background: "rgba(0,0,0,0.5)",
              zIndex: 15,
            }}
            onClick={() => setMobileMenuOpen(false)}
          />
        )}

        {/* Mobile sidebar drawer */}
        {isMobile && (
          <div
            style={{
              position: "fixed",
              left: 0,
              top: 0,
              bottom: 0,
              width: mobileMenuOpen ? 220 : 0,
              zIndex: 25,
              overflow: "hidden",
              transition: "width var(--normal) var(--ease)",
            }}
          >
            <Sidebar collapsed={false} onToggle={() => setMobileMenuOpen(false)} isMobileDrawer />
          </div>
        )}

        {/* Main content */}
        <div className="flex-1 flex flex-col min-h-dvh" style={{ marginLeft }}>
          {children}
        </div>
      </div>
    </MobileMenuContext.Provider>
  );
}
