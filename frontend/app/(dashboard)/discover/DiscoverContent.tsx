"use client";

import { useState, useEffect, useRef } from "react";
import { api } from "@/lib/api";
import { useProfiles } from "@/context/ProfilesContext";
import { Stat } from "@/components/ui/Stat";
import { TierTag, tierColor } from "@/components/ui/TierTag";
import { Bar } from "@/components/ui/Bar";
import type { AnalyzeResponse, DeviceProfileRequest } from "@/lib/types";

interface DiscoveredDevice {
  ip: string;
  mac: string;
  name: string;
  cpu: string;
  ram: string;
  bandwidth: string;
  hasFpu: boolean;
  qri: number;
  tier: any;
  algorithm: string;
  processingTime: number;
}

export function DiscoverContent() {
  const { profiles } = useProfiles();
  const [subnets, setSubnets] = useState("192.168.1.0/24, 10.0.0.0/24");
  const [status, setStatus] = useState<"idle" | "scanning" | "completed">("idle");
  const [progress, setProgress] = useState(0);
  const [logs, setLogs] = useState<string[]>([]);
  const [devices, setDevices] = useState<DiscoveredDevice[]>([]);
  const [scanSpeed, setScanSpeed] = useState<"standard" | "turbo">("standard");
  const consoleEndRef = useRef<HTMLDivElement>(null);

  // Auto scroll terminal logs
  useEffect(() => {
    if (consoleEndRef.current) {
      consoleEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [logs]);

  const addLog = (msg: string) => {
    const time = new Date().toLocaleTimeString();
    setLogs((prev) => [...prev, `[${time}] ${msg}`]);
  };

  const startScan = async () => {
    setStatus("scanning");
    setProgress(0);
    setLogs([]);
    setDevices([]);
    addLog("INITIALIZING AUTOMATED DEVICE DISCOVERY...");
    addLog(`SCOPE DEFINED: [${subnets}]`);
    addLog(`SERVICE SCAN SPEED: [${scanSpeed.toUpperCase()}]`);

    const intervalTime = scanSpeed === "turbo" ? 500 : 1200;

    let scanTargets: any[] = [];
    try {
      addLog("📡 CONNECTING TO AUTOMATION DAEMON & DEPLOYING SCANNER...");
      const res = await api.discover(subnets, scanSpeed);
      scanTargets = res.devices || [];
      addLog(`📡 DAEMON ACQUIRED: Scanning queue initialized with ${scanTargets.length} potential hosts.`);
    } catch (err) {
      addLog(`❌ NETWORK ERROR: Failed to reach discovery daemon: ${err instanceof Error ? err.message : String(err)}`);
      setStatus("idle");
      return;
    }

    let currentStep = 0;
    setProgress(5);

    const runScanStep = async () => {
      if (currentStep >= scanTargets.length) {
        setProgress(100);
        addLog("DISCOVERY COMPLETED.");
        addLog(`INFERENCE RESULTS COMPILED: ${scanTargets.length} ACTIVE HOSTS IDENTIFIED.`);
        setStatus("completed");
        return;
      }

      const target = scanTargets[currentStep];
      const analysis = target.analysis;
      addLog(`SCANNING SUBNET SEGMENT AT ${target.ip.substring(0, target.ip.lastIndexOf('.'))}.X ...`);

      // Simulate network sweep propagation latency
      await new Promise(resolve => setTimeout(resolve, intervalTime * 0.4));

      addLog(`ACTIVE HOST DISCOVERED AT ${target.ip} [MAC: ${target.mac}]`);
      addLog(`QUERYING FIRMWARE CHARACTERISTICS FOR Hostname: "${analysis.device}"...`);
      addLog(`HARDWARE DETAILS DETECTED: [CPU: ${analysis.constraints.cpu}] [RAM: ${analysis.constraints.ram_kb}KB]`);

      // Simulate PQC math inference propagation
      await new Promise(resolve => setTimeout(resolve, intervalTime * 0.3));
      addLog(`COMMENCING REAL-TIME RISK ADAPTIVE POST-QUANTUM RISK INFERENCE...`);

      addLog(`INFERENCE COMPLETE FOR ${target.ip}: QRI ${analysis.qri} (${analysis.qri_tier.toUpperCase()}) -> RECOMMEND ${analysis.selected_algorithm}`);

      const newDevice: DiscoveredDevice = {
        ip: target.ip,
        mac: target.mac,
        name: analysis.device,
        cpu: analysis.constraints.cpu,
        ram: `${analysis.constraints.ram_kb} KB`,
        bandwidth: `${analysis.constraints.bandwidth_kbps} kbps`,
        hasFpu: analysis.constraints.has_fpu,
        qri: analysis.qri,
        tier: analysis.qri_tier,
        algorithm: analysis.selected_algorithm,
        processingTime: analysis.processing_time_ms
      };

      setDevices((prev) => [...prev, newDevice]);

      currentStep++;
      setProgress(Math.round((currentStep / scanTargets.length) * 90) + 5);

      // Wait before scanning the next target
      setTimeout(runScanStep, intervalTime * 0.5);
    };

    setTimeout(runScanStep, intervalTime * 0.5);
  };

  const S: React.CSSProperties = {
    fontFamily: "var(--font-mono)",
    fontSize: "var(--text-12)",
    color: "var(--color-fg-1)",
  };

  return (
    <div style={{ display: "grid", gridTemplateColumns: "220px 1fr", gap: 0, maxWidth: 1100 }}>
      {/* ── Sidebar Controls ── */}
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
          <label className="label" style={{ marginBottom: 8, display: "block" }}>SUBNET SCOPE</label>
          <input
            type="text"
            value={subnets}
            onChange={(e) => setSubnets(e.target.value)}
            disabled={status === "scanning"}
            style={{
              background: "var(--color-ink-2)",
              color: "var(--color-fg-0)",
              border: "1px solid var(--color-rule-dim)",
              padding: "8px 10px",
              fontFamily: "var(--font-mono)",
              fontSize: "var(--text-12)",
              width: "100%",
            }}
          />
        </div>

        <div>
          <label className="label" style={{ marginBottom: 8, display: "block" }}>SCAN SPEED</label>
          <div style={{ display: "flex", gap: 2 }}>
            {(["standard", "turbo"] as const).map((mode) => (
              <button
                key={mode}
                onClick={() => setScanSpeed(mode)}
                disabled={status === "scanning"}
                style={{
                  ...S,
                  flex: 1,
                  padding: "6px 8px",
                  background: scanSpeed === mode ? "var(--color-fg-0)" : "transparent",
                  color: scanSpeed === mode ? "var(--color-ink-0)" : "var(--color-fg-2)",
                  border: "1px solid var(--color-rule)",
                  fontWeight: scanSpeed === mode ? 700 : 400,
                  cursor: status === "scanning" ? "not-allowed" : "pointer",
                  textTransform: "uppercase",
                }}
              >
                {mode}
              </button>
            ))}
          </div>
        </div>

        <div style={{ borderTop: "1px solid var(--color-rule-dim)", paddingTop: 16 }}>
          <button
            onClick={startScan}
            disabled={status === "scanning"}
            style={{
              width: "100%",
              padding: "12px",
              fontFamily: "var(--font-mono)",
              fontSize: "var(--text-12)",
              fontWeight: 700,
              letterSpacing: "0.08em",
              textTransform: "uppercase",
              background: status === "scanning" ? "var(--color-ink-2)" : "var(--color-fg-0)",
              color: status === "scanning" ? "var(--color-fg-2)" : "var(--color-ink-0)",
              border: "none",
              cursor: status === "scanning" ? "not-allowed" : "pointer",
              transition: "all var(--fast) var(--ease)",
            }}
          >
            {status === "scanning" ? "SCANNING SUBNETS…" : "⚡ START AUTOMATION"}
          </button>
        </div>

        {status !== "idle" && (
          <div style={{ borderTop: "1px solid var(--color-rule-dim)", paddingTop: 16 }}>
            <div className="label" style={{ marginBottom: 6 }}>PROGRESS ({progress}%)</div>
            <div style={{ background: "var(--color-ink-2)", height: 6, width: "100%", border: "1px solid var(--color-rule)" }}>
              <div
                style={{
                  height: "100%",
                  background: status === "scanning" ? "var(--color-yellow)" : "var(--color-green)",
                  width: `${progress}%`,
                  transition: "width 0.3s ease-out"
                }}
              />
            </div>
          </div>
        )}
      </aside>

      {/* ── Main Scan Dashboard ── */}
      <div style={{ paddingLeft: 24, display: "flex", flexDirection: "column", gap: 20 }}>
        {/* Radar Simulator Banner */}
        {status === "scanning" && (
          <div
            style={{
              height: 100,
              border: "1px solid var(--color-rule)",
              background: "var(--color-ink-2)",
              position: "relative",
              overflow: "hidden",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            {/* Sweep radar animation */}
            <div
              style={{
                position: "absolute",
                top: "-50%",
                left: "-50%",
                width: "200%",
                height: "200%",
                background: "conic-gradient(from 0deg, rgba(214, 158, 46, 0.15) 0deg, transparent 90deg)",
                transformOrigin: "center center",
                animation: "spin 3s linear infinite",
              }}
            />
            <div style={{ zIndex: 1, display: "flex", flexDirection: "column", alignItems: "center", gap: 6 }}>
              <span className="label blink" style={{ color: "var(--color-yellow)", letterSpacing: "0.15em" }}>📡 RADAR ACTIVESweep pinging network hosts...</span>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-11)", color: "var(--color-fg-2)" }}>Scanning ports 22, 80, 443, 502 (Modbus), 47808 (BACnet)</span>
            </div>
            <style jsx global>{`
              @keyframes spin {
                from { transform: rotate(0deg); }
                to { transform: rotate(360deg); }
              }
            `}</style>
          </div>
        )}

        {/* Live Logs Terminal */}
        <div
          style={{
            border: "1px solid var(--color-rule)",
            background: "var(--color-ink-0)",
            padding: 16,
            display: "flex",
            flexDirection: "column",
            gap: 8,
            height: 240,
            overflowY: "auto",
            fontFamily: "var(--font-mono)",
            fontSize: "var(--text-11)",
            color: "var(--color-green)",
          }}
        >
          <div style={{ borderBottom: "1px solid var(--color-rule-dim)", paddingBottom: 6, marginBottom: 4, display: "flex", justifyContent: "space-between" }}>
            <span className="label" style={{ color: "var(--color-green)" }}>AUTOMATION_DISCOVERY_DAEMON.log</span>
            <span className="label" style={{ color: "var(--color-fg-3)" }}>STATUS: {status.toUpperCase()}</span>
          </div>

          {logs.length === 0 ? (
            <div style={{ color: "var(--color-fg-2)", fontStyle: "italic", paddingTop: 8 }}>
              Daemon listening. Press "START AUTOMATION" to initiate subnet scanning...
            </div>
          ) : (
            logs.map((log, i) => (
              <div key={i} style={{ lineBreak: "anywhere", opacity: i === logs.length - 1 ? 1 : 0.8 }}>
                {log}
              </div>
            ))
          )}
          <div ref={consoleEndRef} />
        </div>

        {/* Aggregate Stats strip */}
        {devices.length > 0 && (
          <div
            className="fade-in"
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(4, 1fr)",
              border: "1px solid var(--color-rule)",
            }}
          >
            <Stat label="DISCOVERED HOSTS" value={devices.length} ruled />
            <Stat label="AVG QRI SCORE" value={(devices.reduce((acc, d) => acc + d.qri, 0) / devices.length).toFixed(1)} ruled />
            <Stat label="NIST COMPLIANCE" value={`${Math.round((devices.filter(d => d.qri < 7.0).length / devices.length) * 100)}%`} ruled />
            <Stat label="TOTAL SIM TIME" value={`${devices.reduce((acc, d) => acc + d.processingTime, 0).toFixed(1)}ms`} />
          </div>
        )}

        {/* Discovered Devices Table */}
        {devices.length > 0 && (
          <div className="fade-in" style={{ border: "1px solid var(--color-rule)", overflowX: "auto" }}>
            <div style={{ background: "var(--color-ink-2)", padding: "10px 16px", borderBottom: "1px solid var(--color-rule)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span className="label" style={{ color: "var(--color-fg-0)" }}>IDENTIFIED NETWORK DEVICES</span>
              <span className="label" style={{ fontSize: "var(--text-10)" }}>AUTOMATIC LIVE INFERENCE INJECTED</span>
            </div>

            {/* Header */}
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "1.2fr 1.2fr 1fr 1fr 0.8fr 1fr",
                padding: "8px 16px",
                background: "var(--color-ink-3)",
                borderBottom: "1px solid var(--color-rule)",
                minWidth: "700px",
              }}
            >
              {["IP ADDRESS", "HOST CHARACTER", "CPU FAMILY", "QRI SCORE", "NIST LVL", "PQC RECOMMENDATION"].map((h) => (
                <span key={h} className="label">{h}</span>
              ))}
            </div>

            {devices.map((d) => (
              <div
                key={d.ip}
                className="hover-surface"
                style={{
                  display: "grid",
                  gridTemplateColumns: "1.2fr 1.2fr 1fr 1fr 0.8fr 1fr",
                  padding: "12px 16px",
                  borderBottom: "1px solid var(--color-rule-dim)",
                  borderLeft: `2px solid ${tierColor(d.tier)}`,
                  alignItems: "center",
                  minWidth: "700px",
                  transition: "background var(--fast) var(--ease)",
                }}
              >
                <div>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-13)", fontWeight: 700, color: "var(--color-fg-0)" }}>
                    {d.ip}
                  </div>
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-10)", color: "var(--color-fg-2)" }}>
                    MAC: {d.mac}
                  </span>
                </div>

                <div>
                  <div style={{ fontFamily: "var(--font-sans)", fontSize: "var(--text-13)", fontWeight: 500, color: "var(--color-fg-1)" }}>
                    {d.name}
                  </div>
                  <TierTag tier={d.tier} />
                </div>

                <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-11)", color: "var(--color-fg-1)" }}>
                  {d.cpu}
                </span>

                <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-14)", fontWeight: 700, color: tierColor(d.tier) }}>
                  {d.qri}
                </span>

                <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-13)", color: "var(--color-fg-0)" }}>
                  L{d.tier === "critical" || d.tier === "high" ? 5 : d.tier === "elevated" ? 3 : 1}
                </span>

                <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-11)", color: "var(--color-fg-0)", fontWeight: 700 }}>
                  {d.algorithm}
                </span>
              </div>
            ))}
          </div>
        )}

        {status === "idle" && (
          <div
            style={{
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              justifyContent: "center",
              minHeight: 280,
              border: "1px solid var(--color-rule-dim)",
              padding: 40,
              textAlign: "center",
              background: "var(--color-ink-2)",
            }}
          >
            <span style={{ fontSize: 32, marginBottom: 12 }}>🤖</span>
            <h3 style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-14)", fontWeight: 700, color: "var(--color-fg-0)", marginBottom: 8, textTransform: "uppercase" }}>
              Automated Discovery Daemon
            </h3>
            <p style={{ fontFamily: "var(--font-sans)", fontSize: "var(--text-12)", color: "var(--color-fg-2)", maxWidth: 500, lineHeight: 1.6 }}>
              In production environments, UNYSIS launches background scan subnets via network port scanning or active device polling (BACnet, Modbus, MQTT). Discovered profiles are automatically simulated against active NIST FIPS PQC algorithms.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
