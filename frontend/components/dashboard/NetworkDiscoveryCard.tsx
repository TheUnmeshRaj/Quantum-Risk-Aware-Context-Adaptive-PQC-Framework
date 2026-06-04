"use client";
// frontend/components/dashboard/NetworkDiscoveryCard.tsx

import { useState, useEffect, useRef } from "react";
import { api } from "@/lib/api";
import { useProfiles } from "@/context/ProfilesContext";
import type { DiscoveredDevice } from "@/lib/types";
import { TierTag, LiveStatus, tierColor } from "@/components/ui/TierTag";
import { Stat } from "@/components/ui/Stat";

interface NetworkDiscoveryCardProps {
  onDevicesDiscovered?: (devices: DiscoveredDevice[]) => void;
}

export function NetworkDiscoveryCard({
  onDevicesDiscovered,
}: NetworkDiscoveryCardProps) {
  const { addProfile } = useProfiles();
  const [subnets, setSubnets] = useState("192.168.1.0/24, 10.0.0.0/24");
  const [scanMode, setScanMode] = useState<"quick" | "deep">("quick");
  const [nmapTargets, setNmapTargets] = useState("192.168.1.88, 10.0.0.42");
  const [status, setStatus] = useState<"idle" | "scanning" | "completed">("idle");
  const [progress, setProgress] = useState(0);
  const [logs, setLogs] = useState<string[]>([]);
  const [devices, setDevices] = useState<DiscoveredDevice[]>([]);
  const [uptime, setUptime] = useState(256);
  const consoleEndRef = useRef<HTMLDivElement>(null);

  // Dynamic uptime tracker
  useEffect(() => {
    const timer = setInterval(() => {
      setUptime((prev) => prev + 1);
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  // Auto scroll terminal logs
  useEffect(() => {
    if (consoleEndRef.current) {
      consoleEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [logs]);

  const addLog = (msg: string) => {
    const timeStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    setLogs((prev) => [...prev, `[${timeStr}] ${msg}`]);
  };

  const startScan = async () => {
    setStatus("scanning");
    setProgress(0);
    setLogs([]);
    setDevices([]);
    addLog("INITIALIZING AUTOMATED DEVICE DISCOVERY...");

    const activeScanType = scanMode === "quick" ? "standard" : "nmap";
    const activeTargets = scanMode === "quick" ? subnets : nmapTargets;
    addLog(`SCOPE DEFINED: [${activeTargets}]`);
    addLog(`PROTOCOL: [${scanMode === "quick" ? "ARP SWEEP (QUICK)" : "NMAP PORT PROBE (DEEP)"}]`);
    addLog(`SCAN VELOCITY: [${scanMode === "quick" ? "TURBO (FAST OUTPUT)" : "STANDARD (PROPER AUDIT)"}]`);

    const intervalTime = scanMode === "quick" ? 200 : 1200;

    let scanTargets: DiscoveredDevice[] = [];
    try {
      addLog("CONNECTING TO AUTOMATION DAEMON & DEPLOYING SCANNER...");
      const res = await api.discover({
        subnets: scanMode === "quick" ? subnets : undefined,
        speed: scanMode === "quick" ? "turbo" : "standard",
        scan_type: activeScanType,
        targets: scanMode === "deep" ? nmapTargets : undefined,
      });
      scanTargets = res.devices || [];
      addLog(`DAEMON ACQUIRED: Scanning queue initialized with ${scanTargets.length} potential hosts.`);
    } catch (err) {
      addLog(`NETWORK ERROR: Failed to reach discovery daemon: ${err instanceof Error ? err.message : String(err)}`);
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
        if (onDevicesDiscovered) {
          onDevicesDiscovered(scanTargets);
        }
        return;
      }

      const target = scanTargets[currentStep];
      const analysis = target.analysis;
      const lastDotIndex = target.ip.lastIndexOf('.');
      const subnetSegment = lastDotIndex !== -1 ? target.ip.substring(0, lastDotIndex) : "192.168.1";
      addLog(`SCANNING SUBNET SEGMENT AT ${subnetSegment}.X ...`);

      // Simulate network sweep propagation latency
      await new Promise((resolve) => setTimeout(resolve, intervalTime * 0.4));

      addLog(`ACTIVE HOST DISCOVERED AT ${target.ip} [MAC: ${target.mac}]`);
      addLog(`QUERYING FIRMWARE CHARACTERISTICS FOR Hostname: "${analysis.device}"...`);

      const cpu = target.profile?.hardware?.cpu || (analysis.constraints as any)?.cpu || "undefined";
      const ram = target.profile?.hardware?.ram_kb || analysis.constraints?.ram_kb || 0;
      addLog(`HARDWARE DETAILS DETECTED: [CPU: ${cpu}] [RAM: ${ram}KB]`);

      // Simulate PQC math inference propagation
      await new Promise((resolve) => setTimeout(resolve, intervalTime * 0.3));
      addLog("COMMENCING REAL-TIME RISK ADAPTIVE POST-QUANTUM RISK INFERENCE...");

      addLog(
        `INFERENCE COMPLETE FOR ${target.ip}: QRI ${analysis.qri} (${analysis.qri_tier.toUpperCase()}) -> RECOMMEND ${analysis.selected_algorithm
        }`
      );

      // Register the discovered profile into the sidebar/context list
      if (target.profile) {
        addProfile(target.profile);
      }

      setDevices((prev) => [...prev, target]);

      currentStep++;
      setProgress(Math.round((currentStep / scanTargets.length) * 90) + 5);

      // Wait before scanning the next target
      setTimeout(runScanStep, intervalTime * 0.5);
    };

    setTimeout(runScanStep, intervalTime * 0.5);
  };

  const docsUrl = process.env.NEXT_PUBLIC_API_URL
    ? `${process.env.NEXT_PUBLIC_API_URL.replace(/\/$/, "")}/docs`
    : "http://localhost:8000/docs";

  return (
    <div
      style={{
        borderBottom: "1px solid var(--color-rule)",
        paddingBottom: 24,
        marginBottom: 24,
      }}
    >
      {/* ── Header Row ── */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "flex-start",
          borderBottom: "1px solid var(--color-rule)",
          paddingBottom: 20,
          marginBottom: 24,
          flexWrap: "wrap",
          gap: 16,
        }}
      >
        <div>
          <h2
            style={{
              fontFamily: "var(--font-sans)",
              fontSize: "var(--text-20)",
              fontWeight: 700,
              color: "var(--color-fg-0)",
              textTransform: "uppercase",
              letterSpacing: "0.04em",
              marginBottom: 4,
            }}
          >
            Discover
          </h2>
          <p
            style={{
              fontFamily: "var(--font-sans)",
              fontSize: "var(--text-12)",
              color: "var(--color-fg-1)",
            }}
          >
            Automated network service scanning and PQC inference
          </p>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 16, flexWrap: "wrap" }}>
          <LiveStatus online={true} />
          <span
            style={{
              fontFamily: "var(--font-mono)",
              fontSize: "var(--text-10)",
              color: "var(--color-fg-1)",
              letterSpacing: "0.1em",
              background: "var(--color-ink-2)",
              padding: "4px 8px",
              border: "1px solid var(--color-rule)",
            }}
          >
            ⏱ {uptime}s uptime
          </span>
          <a
            href={docsUrl}
            target="_blank"
            rel="noopener noreferrer"
            style={{
              fontFamily: "var(--font-mono)",
              fontSize: "var(--text-10)",
              color: "var(--color-fg-1)",
              border: "1px solid var(--color-rule)",
              padding: "4px 8px",
              textDecoration: "none",
              textTransform: "uppercase",
              transition: "all var(--fast) var(--ease)",
            }}
            className="hover-surface focus-ring"
          >
            API DOCS
          </a>
        </div>
      </div>

      {/* ── Main Layout ── */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "240px 1fr",
          gap: 24,
        }}
        className="responsive-grid"
      >
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
            <label className="label" style={{ marginBottom: 8, display: "block" }}>
              DISCOVERY METHOD
            </label>
            <div style={{ display: "flex", gap: 2, marginBottom: 12 }}>
              {(["quick", "deep"] as const).map((mode) => (
                <button
                  key={mode}
                  type="button"
                  onClick={() => setScanMode(mode)}
                  disabled={status === "scanning"}
                  style={{
                    fontFamily: "var(--font-mono)",
                    fontSize: "var(--text-12)",
                    flex: 1,
                    padding: "6px 8px",
                    background: scanMode === mode ? "var(--color-fg-0)" : "transparent",
                    color: scanMode === mode ? "var(--color-ink-0)" : "var(--color-fg-1)",
                    border: "1px solid var(--color-rule)",
                    fontWeight: scanMode === mode ? 700 : 400,
                    cursor: status === "scanning" ? "not-allowed" : "pointer",
                    textTransform: "uppercase",
                  }}
                >
                  {mode === "quick" ? "Quick Sweep" : "Deep Audit"}
                </button>
              ))}
            </div>
            <p
              style={{
                fontFamily: "var(--font-sans)",
                fontSize: "var(--text-11)",
                color: "var(--color-fg-2)",
                lineHeight: 1.4,
              }}
            >
              {scanMode === "quick"
                ? "Fast ARP sweep to discover hosts instantly on subnet."
                : "Thorough Nmap scan mapping BACnet/Modbus ports & services."}
            </p>
          </div>

          {scanMode === "quick" ? (
            <div className="fade-in">
              <label className="label" style={{ marginBottom: 8, display: "block" }}>
                SUBNET SCOPE
              </label>
              <input
                type="text"
                value={subnets}
                onChange={(e) => setSubnets(e.target.value)}
                disabled={status === "scanning"}
                placeholder="e.g., 192.168.1.0/24"
                style={{
                  background: "var(--color-ink-2)",
                  color: "var(--color-fg-0)",
                  border: "1px solid var(--color-rule)",
                  padding: "8px 10px",
                  fontFamily: "var(--font-mono)",
                  fontSize: "var(--text-12)",
                  width: "100%",
                }}
              />
              <span
                style={{
                  display: "block",
                  marginTop: 6,
                  fontFamily: "var(--font-mono)",
                  fontSize: "var(--text-10)",
                  color: "var(--color-fg-2)",
                }}
              >
                Sample: 192.168.1.0/24, 10.0.0.0/24
              </span>
            </div>
          ) : (
            <div className="fade-in">
              <label className="label" style={{ marginBottom: 8, display: "block" }}>
                NMAP TARGETS
              </label>
              <input
                type="text"
                value={nmapTargets}
                onChange={(e) => setNmapTargets(e.target.value)}
                disabled={status === "scanning"}
                placeholder="e.g., scanme.nmap.org"
                style={{
                  background: "var(--color-ink-2)",
                  color: "var(--color-fg-0)",
                  border: "1px solid var(--color-rule)",
                  padding: "8px 10px",
                  fontFamily: "var(--font-mono)",
                  fontSize: "var(--text-12)",
                  width: "100%",
                }}
              />
              <span
                style={{
                  display: "block",
                  marginTop: 6,
                  fontFamily: "var(--font-mono)",
                  fontSize: "var(--text-10)",
                  color: "var(--color-fg-2)",
                }}
              >
                Sample: 192.168.1.88, 10.0.0.42
              </span>
            </div>
          )}

          <div style={{ borderTop: "1px solid var(--color-rule-dim)", paddingTop: 16 }}>
            <button
              type="button"
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
              {status === "scanning" ? "SCANNING SUBNETS…" : "START AUTOMATION"}
            </button>
          </div>

          {status !== "idle" && (
            <div style={{ borderTop: "1px solid var(--color-rule-dim)", paddingTop: 16 }}>
              <div className="label" style={{ marginBottom: 6 }}>
                PROGRESS ({progress}%)
              </div>
              <div
                style={{
                  background: "var(--color-ink-2)",
                  height: 6,
                  width: "100%",
                  border: "1px solid var(--color-rule)",
                }}
              >
                <div
                  style={{
                    height: "100%",
                    background: status === "scanning" ? "var(--color-yellow)" : "var(--color-green)",
                    width: `${progress}%`,
                    transition: "width 0.3s ease-out",
                  }}
                />
              </div>
            </div>
          )}
        </aside>

        {/* ── Main Scan Dashboard ── */}
        <div style={{ display: "flex", flexDirection: "column", gap: 20, minWidth: 0 }}>
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
                  background:
                    "conic-gradient(from 0deg, rgba(214, 158, 46, 0.15) 0deg, transparent 90deg)",
                  transformOrigin: "center center",
                  animation: "spin 3s linear infinite",
                }}
              />
              <div
                style={{
                  zIndex: 1,
                  display: "flex",
                  flexDirection: "column",
                  alignItems: "center",
                  gap: 6,
                  textAlign: "center",
                }}
              >
                <span
                  className="label blink"
                  style={{ color: "var(--color-yellow)", letterSpacing: "0.15em" }}
                >
                  📡 RADAR ACTIVE: Sweep pinging network hosts...
                </span>
                <span
                  style={{
                    fontFamily: "var(--font-mono)",
                    fontSize: "var(--text-11)",
                    color: "var(--color-fg-2)",
                  }}
                >
                  Scanning ports 22, 80, 443, 502 (Modbus), 47808 (BACnet)
                </span>
              </div>
              <style jsx global>{`
                @keyframes spin {
                  from {
                    transform: rotate(0deg);
                  }
                  to {
                    transform: rotate(360deg);
                  }
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
            <div
              style={{
                borderBottom: "1px solid var(--color-rule-dim)",
                paddingBottom: 6,
                marginBottom: 4,
                display: "flex",
                justifyContent: "space-between",
              }}
            >
              <span className="label" style={{ color: "var(--color-green)" }}>
                AUTOMATION_DISCOVERY_DAEMON.log
              </span>
              <span className="label" style={{ color: "var(--color-fg-2)" }}>
                STATUS: {status.toUpperCase()}
              </span>
            </div>

            {logs.length === 0 ? (
              <div style={{ color: "var(--color-fg-2)", fontStyle: "italic", paddingTop: 8 }}>
                Daemon listening. Press "START AUTOMATION" to initiate subnet scanning...
              </div>
            ) : (
              logs.map((log, i) => (
                <div
                  key={i}
                  style={{
                    lineBreak: "anywhere",
                    opacity: i === logs.length - 1 ? 1 : 0.8,
                  }}
                >
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
                gridTemplateColumns: "repeat(auto-fit, minmax(120px, 1fr))",
                border: "1px solid var(--color-rule)",
              }}
            >
              <Stat label="DISCOVERED HOSTS" value={devices.length} ruled />
              <Stat
                label="AVG QRI SCORE"
                value={(devices.reduce((acc, d) => acc + d.analysis.qri, 0) / devices.length).toFixed(1)}
                ruled
                color="var(--color-blue)"
              />
              <Stat
                label="NIST COMPLIANCE"
                value={`${Math.round(
                  (devices.filter((d) => d.analysis.qri < 7.0).length / devices.length) * 100
                )}%`}
                ruled
                color="var(--color-green)"
              />
              <Stat
                label="TOTAL SIM TIME"
                value={`${devices.reduce((acc, d) => acc + d.analysis.processing_time_ms, 0).toFixed(1)}ms`}
                ruled
                color="var(--color-yellow)"
              />
            </div>
          )}

          {/* Discovered Devices Table */}
          {devices.length > 0 && (
            <div
              className="fade-in"
              style={{ border: "1px solid var(--color-rule)", overflowX: "auto" }}
            >
              <div
                style={{
                  background: "var(--color-ink-2)",
                  padding: "10px 16px",
                  borderBottom: "1px solid var(--color-rule)",
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                }}
              >
                <span className="label" style={{ color: "var(--color-fg-0)" }}>
                  IDENTIFIED NETWORK DEVICES
                </span>
                <span className="label" style={{ fontSize: "var(--text-10)" }}>
                  AUTOMATIC LIVE INFERENCE INJECTED
                </span>
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
                {["IP ADDRESS", "HOST CHARACTER", "CPU FAMILY", "QRI SCORE", "NIST LVL", "PQC RECOMMENDATION"].map(
                  (h) => (
                    <span key={h} className="label">
                      {h}
                    </span>
                  )
                )}
              </div>

              {/* Rows */}
              {devices.map((d) => (
                <div
                  key={d.ip}
                  className="hover-surface"
                  style={{
                    display: "grid",
                    gridTemplateColumns: "1.2fr 1.2fr 1fr 1fr 0.8fr 1fr",
                    padding: "12px 16px",
                    borderBottom: "1px solid var(--color-rule-dim)",
                    borderLeft: `2px solid ${tierColor(d.analysis.qri_tier)}`,
                    alignItems: "center",
                    minWidth: "700px",
                    transition: "background var(--fast) var(--ease)",
                  }}
                >
                  <div>
                    <div
                      style={{
                        fontFamily: "var(--font-mono)",
                        fontSize: "var(--text-13)",
                        fontWeight: 700,
                        color: "var(--color-fg-0)",
                      }}
                    >
                      {d.ip}
                    </div>
                    <span
                      style={{
                        fontFamily: "var(--font-mono)",
                        fontSize: "var(--text-10)",
                        color: "var(--color-fg-2)",
                      }}
                    >
                      MAC: {d.mac}
                    </span>
                  </div>

                  <div>
                    <div
                      style={{
                        fontFamily: "var(--font-sans)",
                        fontSize: "var(--text-13)",
                        fontWeight: 500,
                        color: "var(--color-fg-1)",
                      }}
                    >
                      {d.analysis.device}
                    </div>
                    <TierTag tier={d.analysis.qri_tier} />
                  </div>

                  <span
                    style={{
                      fontFamily: "var(--font-mono)",
                      fontSize: "var(--text-11)",
                      color: "var(--color-fg-1)",
                    }}
                  >
                    {d.profile?.hardware?.cpu || (d.analysis?.constraints as any)?.cpu || "Unknown"}
                  </span>

                  <span
                    style={{
                      fontFamily: "var(--font-mono)",
                      fontSize: "var(--text-14)",
                      fontWeight: 700,
                      color: tierColor(d.analysis.qri_tier),
                    }}
                  >
                    {d.analysis.qri.toFixed(1)}
                  </span>

                  <span
                    style={{
                      fontFamily: "var(--font-mono)",
                      fontSize: "var(--text-13)",
                      color: "var(--color-fg-0)",
                    }}
                  >
                    L
                    {d.analysis.qri_tier === "CRITICAL" || d.analysis.qri_tier === "HIGH"
                      ? 5
                      : d.analysis.qri_tier === "ELEVATED"
                        ? 3
                        : 1}
                  </span>

                  <span
                    style={{
                      fontFamily: "var(--font-mono)",
                      fontSize: "var(--text-11)",
                      color: "var(--color-fg-0)",
                      fontWeight: 700,
                    }}
                  >
                    {d.analysis.selected_algorithm}
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
              <h3
                style={{
                  fontFamily: "var(--font-mono)",
                  fontSize: "var(--text-14)",
                  fontWeight: 700,
                  color: "var(--color-fg-0)",
                  marginBottom: 8,
                  textTransform: "uppercase",
                }}
              >
                Automated Discovery Daemon
              </h3>
              <p
                style={{
                  fontFamily: "var(--font-sans)",
                  fontSize: "var(--text-12)",
                  color: "var(--color-fg-2)",
                  maxWidth: 500,
                  lineHeight: 1.6,
                }}
              >
                In production environments, UNISYS launches background subnet scans via network port scanning or active device polling (BACnet, Modbus, MQTT). Discovered profiles are automatically simulated against active NIST FIPS PQC algorithms.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
