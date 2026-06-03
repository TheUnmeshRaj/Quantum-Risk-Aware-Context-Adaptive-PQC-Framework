"use client";
// frontend/components/dashboard/NetworkDiscoveryCard.tsx

import { useState } from "react";
import { api } from "@/lib/api";
import { useProfiles } from "@/context/ProfilesContext";
import type { DiscoveredDevice } from "@/lib/types";
import { TierTag } from "@/components/ui/TierTag";

interface NetworkDiscoveryCardProps {
  onDevicesDiscovered?: (devices: DiscoveredDevice[]) => void;
}

export function NetworkDiscoveryCard({
  onDevicesDiscovered,
}: NetworkDiscoveryCardProps) {
  const { addProfile } = useProfiles();
  const [devices, setDevices] = useState<DiscoveredDevice[]>([]);
  const [scanType, setScanType] = useState<"standard" | "nmap">("standard");
  const [scanTargets, setScanTargets] = useState("192.168.1.0/24");
  const [importedCount, setImportedCount] = useState(0);
  const [warning, setWarning] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);

  const handleScan = async () => {
    setScanning(true);
    setError(null);
    setWarning(null);
    setDevices([]);
    setImportedCount(0);

    try {
      const response = await api.discoverStream(
        {
          subnets: scanType === "standard" ? scanTargets : "",
          speed: "standard",
          scan_type: scanType,
          targets: scanType === "nmap" ? scanTargets : undefined,
        },
        {
          onDevice: (device) => {
            setDevices((prev) => [...prev, device]);
            setImportedCount((prev) => prev + 1);
            addProfile(device.profile);
          },
          onWarning: (nextWarning) => {
            setWarning(nextWarning);
          },
        },
      );

      if (onDevicesDiscovered) {
        onDevicesDiscovered(response.devices);
      }
    } catch (err: any) {
      setWarning(null);
      setError(err.message || "Scan failed");
    } finally {
      setScanning(false);
    }
  };

  return (
    <div
      style={{
        borderBottom: "1px solid var(--color-rule)",
        paddingBottom: 24,
        marginBottom: 24,
      }}
    >
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: 12,
          flexWrap: "wrap",
          gap: 12,
        }}
      >
        <div>
          <div className="label">
            NETWORK DISCOVERY (ARP + mDNS + optional nmap)
          </div>
          <div
            style={{ marginTop: 8, display: "flex", gap: 8, flexWrap: "wrap" }}
          >
            {(["standard", "nmap"] as const).map((mode) => (
              <button
                key={mode}
                type="button"
                onClick={() => setScanType(mode)}
                style={{
                  fontFamily: "var(--font-mono)",
                  fontSize: "var(--text-10)",
                  padding: "4px 8px",
                  border: "1px solid var(--color-rule)",
                  background:
                    scanType === mode ? "var(--color-fg-0)" : "transparent",
                  color:
                    scanType === mode
                      ? "var(--color-ink-0)"
                      : "var(--color-fg-1)",
                  cursor: "pointer",
                }}
              >
                {mode === "nmap" ? "Deep nmap" : "Standard"}
              </button>
            ))}
          </div>
          {scanType === "nmap" ? (
            <div style={{ marginTop: 10, width: 320 }}>
              <label
                className="label"
                style={{ display: "block", marginBottom: 6 }}
              >
                NMAP TARGETS
              </label>
              <input
                type="text"
                value={scanTargets}
                onChange={(e) => setScanTargets(e.target.value)}
                placeholder="example.com, 198.51.100.0/24"
                style={{
                  width: "100%",
                  padding: "8px 10px",
                  fontFamily: "var(--font-mono)",
                  fontSize: "var(--text-12)",
                  background: "var(--color-ink-2)",
                  color: "var(--color-fg-0)",
                  border: "1px solid var(--color-rule)",
                }}
              />
            </div>
          ) : null}
        </div>
        <button
          onClick={handleScan}
          disabled={scanning}
          style={{
            padding: "6px 12px",
            border: "1px solid var(--color-rule)",
            background: "transparent",
            color: "var(--color-fg-0)",
            cursor: scanning ? "not-allowed" : "pointer",
            opacity: scanning ? 0.6 : 1,
            borderRadius: 4,
            fontSize: "var(--text-12)",
            fontWeight: 500,
          }}
        >
          {scanning ? "⟳ Scanning..." : "Scan Network"}
        </button>
      </div>

      {error && (
        <div
          style={{
            padding: "10px 16px",
            border: "1px solid var(--color-rule)",
            borderLeft: "2px solid var(--color-red)",
            marginBottom: 12,
            fontSize: "var(--text-12)",
            color: "var(--color-red)",
          }}
        >
          {error}
        </div>
      )}
      {warning && (
        <div
          style={{
            padding: "10px 16px",
            border: "1px solid var(--color-rule)",
            borderLeft: "2px solid var(--color-yellow)",
            marginBottom: 12,
            fontSize: "var(--text-12)",
            color: "var(--color-yellow)",
          }}
        >
          {warning}
        </div>
      )}
      {devices.length > 0 &&
        (devices[0] as any).profile &&
        (devices[0] as any).analysis &&
        false}

      {devices.length > 0 ? (
        <>
          {importedCount > 0 && (
            <div
              style={{
                marginBottom: 12,
                fontSize: "var(--text-12)",
                color: "var(--color-fg-1)",
              }}
            >
              {importedCount} discovered device{importedCount === 1 ? "" : "s"}{" "}
              imported into the analysis device list.
            </div>
          )}
          <div
            style={{
              display: "flex",
              flexDirection: "column",
              gap: 8,
              maxHeight: 400,
              overflowY: "auto",
            }}
          >
            {devices.map((d, i) => (
              <div
                key={i}
                style={{
                  padding: 12,
                  border: "1px solid var(--color-rule)",
                  borderRadius: 4,
                  display: "grid",
                  gridTemplateColumns: "1fr 1fr 1fr auto",
                  gap: 12,
                  fontSize: "var(--text-12)",
                }}
              >
                <div>
                  <div className="label" style={{ marginBottom: 4 }}>
                    IP
                  </div>
                  <div style={{ fontFamily: "var(--font-mono)" }}>{d.ip}</div>
                </div>
                <div>
                  <div className="label" style={{ marginBottom: 4 }}>
                    MAC
                  </div>
                  <div
                    style={{
                      fontFamily: "var(--font-mono)",
                      fontSize: "var(--text-11)",
                    }}
                  >
                    {d.mac}
                  </div>
                </div>
                <div>
                  <div className="label" style={{ marginBottom: 4 }}>
                    DEVICE
                  </div>
                  <div
                    style={{
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {d.analysis.device}
                  </div>
                </div>
                <div style={{ display: "flex", alignItems: "flex-end" }}>
                  <TierTag tier={d.analysis.qri_tier} qri={d.analysis.qri} />
                </div>
              </div>
            ))}
          </div>
        </>
      ) : (
        <div
          style={{
            padding: "20px",
            border: "1px solid var(--color-rule)",
            textAlign: "center",
            color: "var(--color-fg-1)",
            fontSize: "var(--text-12)",
          }}
        >
          {scanning ? (
            <>⟳ Scanning network...</>
          ) : (
            <>Click "Scan Network" to discover devices on your local subnet</>
          )}
        </div>
      )}
    </div>
  );
}
