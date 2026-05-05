"use client";
import { useState } from "react";
import { Sidebar } from "./Sidebar";

export default function DashboardShell({ children }: { children: React.ReactNode }) {
  const [collapsed, setCollapsed] = useState(false);
  return (
    <div className="min-h-dvh">
      <Sidebar collapsed={collapsed} onToggle={() => setCollapsed((c) => !c)} />
      <div className="flex-1 flex flex-col min-h-dvh" style={{ marginLeft: collapsed ? 64 : 220 }}>
        {children}
      </div>
    </div>
  );
}
