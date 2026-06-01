"use client";
// app/(dashboard)/fleet/FleetContent.tsx

import { useState, useRef } from "react";
import { api } from "@/lib/api";
import { useProfiles } from "@/context/ProfilesContext";
import { Stat } from "@/components/ui/Stat";
import { Skel } from "@/components/ui/Skeleton";
import { TierTag, tierColor } from "@/components/ui/TierTag";
import { Bar } from "@/components/ui/Bar";
import type { SimulateResponse, DeviceProfileRequest } from "@/lib/types";
import * as XLSX from "xlsx";

const ADVERSARY_OPTIONS = ["low", "medium", "nation_state"] as const;

export function FleetContent() {
  const { profiles } = useProfiles();
  const [activeTab, setActiveTab] = useState<"preset" | "upload">("preset");
  const [adversary, setAdversary] = useState<"low" | "medium" | "nation_state">("medium");
  const [result,    setResult]    = useState<SimulateResponse | null>(null);
  const [loading,   setLoading]   = useState(false);
  const [error,     setError]     = useState<string | null>(null);

  // Custom Upload state
  const [customDevices, setCustomDevices] = useState<DeviceProfileRequest[]>([]);
  const [validationErrors, setValidationErrors] = useState<string[]>([]);
  const [fileName, setFileName] = useState<string | null>(null);
  const [pastedCSV, setPastedCSV] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Native CSV Parser
  function parseCSVText(text: string): any[] {
    const lines = text.split(/\r?\n/);
    if (lines.length < 2) return [];

    const headers = parseCSVLine(lines[0]);
    const resultRows: any[] = [];

    for (let i = 1; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;
      const values = parseCSVLine(line);
      const rowObj: any = {};
      headers.forEach((h, index) => {
        rowObj[h] = values[index] !== undefined ? values[index] : "";
      });
      resultRows.push(rowObj);
    }
    return resultRows;
  }

  function parseCSVLine(line: string): string[] {
    const parsed: string[] = [];
    let current = "";
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
      const char = line[i];
      if (char === '"') {
        inQuotes = !inQuotes;
      } else if (char === ',' && !inQuotes) {
        parsed.push(current.trim());
        current = "";
      } else {
        current += char;
      }
    }
    parsed.push(current.trim());
    return parsed.map(val => val.replace(/^"|"$/g, '').trim());
  }

  function parseAndValidateRow(row: any, index: number): DeviceProfileRequest | string {
    const findVal = (keys: string[]) => {
      const foundKey = Object.keys(row).find(k => keys.includes(k.toLowerCase().trim()));
      return foundKey ? row[foundKey] : undefined;
    };

    const name = String(findVal(["name", "device", "profile name", "device name", "profile"]) || `Device ${index}`).trim();
    const description = String(findVal(["description", "desc", "notes"]) || "").trim();
    
    const data_sensitivity = Number(findVal(["data_sensitivity", "sensitivity", "data sensitivity"]) ?? 5.0);
    if (isNaN(data_sensitivity) || data_sensitivity < 0 || data_sensitivity > 10) {
      return `Row ${index} (${name}): Data Sensitivity must be a number between 0 and 10.`;
    }

    const exposure_level = Number(findVal(["exposure_level", "exposure", "exposure level"]) ?? 5.0);
    if (isNaN(exposure_level) || exposure_level < 0 || exposure_level > 10) {
      return `Row ${index} (${name}): Exposure Level must be a number between 0 and 10.`;
    }

    const data_lifetime_yrs = Number(findVal(["data_lifetime_yrs", "lifetime", "data lifetime", "lifetime years", "lifetime_yrs"]) ?? 5.0);
    if (isNaN(data_lifetime_yrs) || data_lifetime_yrs < 0) {
      return `Row ${index} (${name}): Data Lifetime (Years) must be a positive number.`;
    }

    const threat_window = Number(findVal(["threat_window", "threat", "threat window", "threat_window"]) ?? 5.0);
    if (isNaN(threat_window) || threat_window < 0 || threat_window > 10) {
      return `Row ${index} (${name}): Threat Window must be a number between 0 and 10.`;
    }

    let advVal = String(findVal(["adversary", "threat actor", "adversary model"]) || "medium").toLowerCase().replace("-", "_").trim();
    if (advVal === "nation state") advVal = "nation_state";
    if (advVal !== "low" && advVal !== "medium" && advVal !== "nation_state") {
      return `Row ${index} (${name}): Adversary must be 'low', 'medium', or 'nation_state'. Got '${advVal}'.`;
    }
    const adversary = advVal as "low" | "medium" | "nation_state";

    const ram_kb = Number(findVal(["ram_kb", "ram", "ram kb", "memory"]) ?? 1024);
    if (isNaN(ram_kb) || ram_kb <= 0) {
      return `Row ${index} (${name}): RAM (KB) must be a positive number.`;
    }

    const cpu = String(findVal(["cpu", "processor", "cpu family"]) || "Generic CPU").trim();

    let fpuVal = findVal(["has_fpu", "fpu", "has fpu", "hardware fpu"]);
    let has_fpu = false;
    if (typeof fpuVal === "boolean") {
      has_fpu = fpuVal;
    } else if (fpuVal !== undefined && fpuVal !== null) {
      const s = String(fpuVal).toLowerCase().trim();
      has_fpu = s === "true" || s === "yes" || s === "1" || s === "y";
    }

    const bandwidth_kbps = Number(findVal(["bandwidth_kbps", "bandwidth", "bandwidth kbps", "network"]) ?? 1000);
    if (isNaN(bandwidth_kbps) || bandwidth_kbps <= 0) {
      return `Row ${index} (${name}): Bandwidth (kbps) must be a positive number.`;
    }

    return {
      name,
      description: description || undefined,
      data_sensitivity,
      exposure_level,
      data_lifetime_yrs,
      threat_window,
      adversary,
      hardware: {
        ram_kb,
        cpu,
        has_fpu,
        bandwidth_kbps,
      }
    };
  }

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setFileName(file.name);
    setValidationErrors([]);
    setCustomDevices([]);
    setResult(null);

    const fileReader = new FileReader();

    if (file.name.endsWith(".csv")) {
      fileReader.onload = (event) => {
        const text = event.target?.result as string;
        processRawRows(parseCSVText(text));
      };
      fileReader.readAsText(file);
    } else if (file.name.endsWith(".xlsx") || file.name.endsWith(".xls")) {
      fileReader.onload = (event) => {
        try {
          const buffer = event.target?.result as ArrayBuffer;
          const workbook = XLSX.read(new Uint8Array(buffer), { type: "array" });
          const sheetName = workbook.SheetNames[0];
          const worksheet = workbook.Sheets[sheetName];
          const jsonData = XLSX.utils.sheet_to_json(worksheet);
          processRawRows(jsonData);
        } catch (err) {
          setValidationErrors([`Failed to parse Excel sheet: ${err instanceof Error ? err.message : String(err)}`]);
        }
      };
      fileReader.readAsArrayBuffer(file);
    } else {
      setValidationErrors(["Unsupported file format. Please upload a .csv or .xlsx file."]);
    }
  };

  const handlePasteSubmit = () => {
    if (!pastedCSV.trim()) {
      setError("Please paste some CSV data first.");
      return;
    }
    setFileName("Pasted Data");
    setValidationErrors([]);
    setCustomDevices([]);
    setResult(null);
    processRawRows(parseCSVText(pastedCSV));
  };

  const processRawRows = (rawRows: any[]) => {
    if (rawRows.length === 0) {
      setValidationErrors(["The file or text appears to be empty."]);
      return;
    }

    const parsedDevices: DeviceProfileRequest[] = [];
    const errors: string[] = [];

    rawRows.forEach((row, i) => {
      const parsed = parseAndValidateRow(row, i + 1);
      if (typeof parsed === "string") {
        errors.push(parsed);
      } else {
        parsedDevices.push(parsed);
      }
    });

    if (errors.length > 0) {
      setValidationErrors(errors);
    } else {
      setCustomDevices(parsedDevices);
      setError(null);
    }
  };

  async function runPresetFleet() {
    setLoading(true); setError(null);
    try {
      const payload = profiles.map((p) => ({
        ...p, adversary,
        hardware: { ...p.hardware, ram_kb: Math.min(p.hardware.ram_kb, 2_000_000) },
      }));
      setResult(await api.simulate(payload));
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "error");
    } finally { setLoading(false); }
  }

  async function runCustomFleet() {
    if (customDevices.length === 0) {
      setError("No valid custom devices loaded to simulate.");
      return;
    }
    setLoading(true); setError(null);
    try {
      const payload = customDevices.map((p) => ({
        ...p,
        hardware: { ...p.hardware, ram_kb: Math.min(p.hardware.ram_kb, 2_000_000) },
      }));
      setResult(await api.simulate(payload));
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "error running fleet simulation");
    } finally { setLoading(false); }
  }

  const resetCustomUpload = () => {
    setCustomDevices([]);
    setValidationErrors([]);
    setFileName(null);
    setPastedCSV("");
    setResult(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  };

  const fm = result?.fleet_metrics;

  const codeTemplate = `name,description,data_sensitivity,exposure_level,data_lifetime_yrs,threat_window,adversary,ram_kb,cpu,has_fpu,bandwidth_kbps
Smart Camera,Outdoor security camera,5.0,7.5,5,4.0,medium,262144,ARM Cortex-A7,true,10000
Medical Device,Hospital heart monitor,9.5,2.0,15,8.5,nation_state,128,ARM Cortex-M4,false,100`;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 24, maxWidth: 1200, width: "100%" }}>

      {/* ── Tabs ── */}
      <div style={{ display: "flex", gap: 2, borderBottom: "1px solid var(--color-rule)", paddingBottom: 0 }}>
        <button
          onClick={() => {
            setActiveTab("preset");
            setResult(null);
            setError(null);
          }}
          style={{
            fontFamily: "var(--font-mono)",
            fontSize: "var(--text-12)",
            padding: "10px 20px",
            background: activeTab === "preset" ? "var(--color-ink-3)" : "transparent",
            color: activeTab === "preset" ? "var(--color-fg-0)" : "var(--color-fg-2)",
            border: "1px solid var(--color-rule)",
            borderBottom: activeTab === "preset" ? "1px solid var(--color-ink-3)" : "1px solid var(--color-rule)",
            marginBottom: -1,
            cursor: "pointer",
            fontWeight: activeTab === "preset" ? 700 : 400,
          }}
        >
          PRESET FLEET ({profiles.length})
        </button>
        <button
          onClick={() => {
            setActiveTab("upload");
            setResult(null);
            setError(null);
          }}
          style={{
            fontFamily: "var(--font-mono)",
            fontSize: "var(--text-12)",
            padding: "10px 20px",
            background: activeTab === "upload" ? "var(--color-ink-3)" : "transparent",
            color: activeTab === "upload" ? "var(--color-fg-0)" : "var(--color-fg-2)",
            border: "1px solid var(--color-rule)",
            borderBottom: activeTab === "upload" ? "1px solid var(--color-ink-3)" : "1px solid var(--color-rule)",
            marginBottom: -1,
            cursor: "pointer",
            fontWeight: activeTab === "upload" ? 700 : 400,
          }}
        >
          UPLOAD CUSTOM FLEET (EXCEL/CSV)
        </button>
      </div>

      {/* ── Tab Contents ── */}
      {activeTab === "preset" ? (
        <div style={{ display: "flex", alignItems: "center", gap: 0, borderBottom: "1px solid var(--color-rule-dim)", paddingBottom: 16 }}>
          <div style={{ display: "flex", gap: 0, marginRight: 20 }}>
            {ADVERSARY_OPTIONS.map((a) => (
              <button
                key={a}
                onClick={() => { setAdversary(a); setResult(null); }}
                style={{
                  fontFamily: "var(--font-mono)",
                  fontSize: "var(--text-11)",
                  letterSpacing: "0.06em",
                  textTransform: "uppercase",
                  padding: "6px 14px",
                  background: adversary === a ? "var(--color-fg-0)" : "transparent",
                  color: adversary === a ? "var(--color-ink-0)" : "var(--color-fg-2)",
                  border: "1px solid var(--color-rule)",
                  borderRight: "none",
                  cursor: "pointer",
                  transition: "all var(--fast) var(--ease)",
                }}
              >
                {a}
              </button>
            ))}
            <div style={{ width: 1, background: "var(--color-rule)" }} />
          </div>

          <button
            onClick={runPresetFleet}
            disabled={loading}
            style={{
              fontFamily: "var(--font-mono)",
              fontSize: "var(--text-11)",
              letterSpacing: "0.08em",
              textTransform: "uppercase",
              padding: "6px 20px",
              background: loading ? "var(--color-ink-2)" : "var(--color-fg-0)",
              color: loading ? "var(--color-fg-2)" : "var(--color-ink-0)",
              border: "none",
              fontWeight: 700,
              cursor: loading ? "not-allowed" : "pointer",
              transition: "all var(--fast) var(--ease)",
            }}
          >
            {loading ? "SIMULATING PRESENTS…" : `RUN PRESENTS · ${profiles.length} DEVICES`}
          </button>

          {error && (
            <span style={{ marginLeft: 16, fontFamily: "var(--font-mono)", fontSize: "var(--text-11)", color: "var(--color-red)" }}>
              {error}
            </span>
          )}
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 16, borderBottom: "1px solid var(--color-rule-dim)", paddingBottom: 20 }}>
          {/* Custom Upload Workspace */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
            {/* Left Col: File Drag-drop &Paste */}
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              <span className="label">1. UPLOAD CSV OR EXCEL FILE (.xlsx, .xls, .csv)</span>
              <div
                style={{
                  border: "1px dashed var(--color-rule)",
                  padding: "20px 16px",
                  background: "var(--color-ink-3)",
                  textAlign: "center",
                  display: "flex",
                  flexDirection: "column",
                  alignItems: "center",
                  gap: 12,
                }}
              >
                <input
                  type="file"
                  ref={fileInputRef}
                  onChange={handleFileUpload}
                  accept=".csv, .xlsx, .xls"
                  style={{ display: "none" }}
                />
                <button
                  onClick={() => fileInputRef.current?.click()}
                  style={{
                    background: "var(--color-fg-0)",
                    color: "var(--color-ink-0)",
                    border: "none",
                    padding: "8px 16px",
                    fontFamily: "var(--font-mono)",
                    fontSize: "var(--text-11)",
                    fontWeight: 700,
                    cursor: "pointer",
                    textTransform: "uppercase",
                  }}
                >
                  CHOOSE FILE
                </button>
                {fileName ? (
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-11)", color: "var(--color-green)" }}>
                    ✓ {fileName} ({customDevices.length} devices loaded)
                  </span>
                ) : (
                  <span className="label" style={{ color: "var(--color-fg-3)" }}>
                    No file selected
                  </span>
                )}
              </div>

              <div style={{ display: "flex", flexDirection: "column", gap: 6, marginTop: 4 }}>
                <span className="label">OR PASTE RAW CSV CONTENT</span>
                <textarea
                  value={pastedCSV}
                  onChange={(e) => setPastedCSV(e.target.value)}
                  placeholder="name,description,data_sensitivity,exposure_level,..."
                  rows={4}
                  style={{
                    background: "var(--color-ink-2)",
                    color: "var(--color-fg-0)",
                    border: "1px solid var(--color-rule-dim)",
                    fontFamily: "var(--font-mono)",
                    fontSize: "var(--text-11)",
                    padding: 8,
                    width: "100%",
                    resize: "vertical"
                  }}
                />
                <button
                  onClick={handlePasteSubmit}
                  style={{
                    alignSelf: "flex-end",
                    background: "transparent",
                    border: "1px solid var(--color-rule)",
                    color: "var(--color-fg-1)",
                    padding: "4px 10px",
                    fontFamily: "var(--font-mono)",
                    fontSize: "var(--text-10)",
                    cursor: "pointer"
                  }}
                >
                  PARSE PASTED CSV
                </button>
              </div>
            </div>

            {/* Right Col: Guide & Template */}
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              <span className="label">CSV / EXCEL TEMPLATE STRUCTURE</span>
              <div
                style={{
                  background: "var(--color-ink-2)",
                  border: "1px solid var(--color-rule-dim)",
                  padding: 12,
                  fontFamily: "var(--font-mono)",
                  fontSize: "var(--text-10)",
                  color: "var(--color-fg-1)",
                  overflowX: "auto"
                }}
              >
                <pre style={{ margin: 0 }}>{codeTemplate}</pre>
              </div>
              <p style={{ fontFamily: "var(--font-sans)", fontSize: "var(--text-12)", color: "var(--color-fg-2)", lineHeight: 1.5, margin: 0 }}>
                💡 <strong>Instructions:</strong> Ensure your column headers match the keywords in the template. The parser will automatically map fields, including checking for valid risk scores (0–10) and hardware capabilities. Casing is ignored, and FPU can be represented by <code>true/false</code> or <code>yes/no</code>.
              </p>
            </div>
          </div>

          {/* Validation Errors panel */}
          {validationErrors.length > 0 && (
            <div style={{ background: "rgba(224, 86, 86, 0.08)", border: "1px solid var(--color-red)", padding: 12 }}>
              <div className="label" style={{ color: "var(--color-red)", marginBottom: 8 }}>❌ VALIDATION ERRORS ({validationErrors.length})</div>
              <ul style={{ margin: 0, paddingLeft: 16, display: "flex", flexDirection: "column", gap: 4 }}>
                {validationErrors.slice(0, 5).map((err, idx) => (
                  <li key={idx} style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-11)", color: "var(--color-red)" }}>{err}</li>
                ))}
                {validationErrors.length > 5 && (
                  <li style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-11)", color: "var(--color-red)", listStyleType: "none", marginTop: 4 }}>
                    ... and {validationErrors.length - 5} more errors.
                  </li>
                )}
              </ul>
            </div>
          )}

          {/* Action buttons */}
          <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
            <button
              onClick={runCustomFleet}
              disabled={loading || customDevices.length === 0}
              style={{
                fontFamily: "var(--font-mono)",
                fontSize: "var(--text-11)",
                letterSpacing: "0.08em",
                textTransform: "uppercase",
                padding: "8px 24px",
                background: loading || customDevices.length === 0 ? "var(--color-ink-2)" : "var(--color-fg-0)",
                color: loading || customDevices.length === 0 ? "var(--color-fg-2)" : "var(--color-ink-0)",
                border: "none",
                fontWeight: 700,
                cursor: loading || customDevices.length === 0 ? "not-allowed" : "pointer"
              }}
            >
              {loading ? "SIMULATING CUSTOM FLEET…" : `RUN CUSTOM SIMULATOR · ${customDevices.length} DEVICES`}
            </button>
            {(fileName || pastedCSV || customDevices.length > 0) && (
              <button
                onClick={resetCustomUpload}
                style={{
                  background: "transparent",
                  color: "var(--color-fg-2)",
                  border: "1px solid var(--color-rule)",
                  padding: "7px 16px",
                  fontFamily: "var(--font-mono)",
                  fontSize: "var(--text-11)",
                  cursor: "pointer"
                }}
              >
                RESET UPLOADER
              </button>
            )}
            {error && (
              <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-11)", color: "var(--color-red)", marginLeft: 10 }}>
                {error}
              </span>
            )}
          </div>
        </div>
      )}

      {/* ── KPI strip ── */}
      {loading && !fm ? (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", border: "1px solid var(--color-rule)" }}>
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} style={{ padding: 20, borderRight: i < 4 ? "1px solid var(--color-rule)" : undefined }}>
              <Skel h={8} w={50} />
              <div style={{ marginTop: 12 }}><Skel h={22} w={70} /></div>
            </div>
          ))}
        </div>
      ) : fm ? (
        <div
          className="fade-in"
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(5, 1fr)",
            border: "1px solid var(--color-rule)",
          }}
        >
          <Stat label="DEVICES"    value={fm.device_count}              ruled />
          <Stat label="AVG QRI"    value={fm.avg_qri}                   sub={`max ${fm.max_qri}`} />
          <Stat label="CRITICAL"   value={fm.critical_count}            color={fm.critical_count > 0 ? "var(--color-red)" : undefined} sub={`${fm.high_count} HIGH`} />
          <Stat label="COMPLIANCE" value={`${fm.avg_compliance_score}%`} />
          <Stat label="TOTAL TIME" value={`${fm.total_processing_ms.toFixed(1)}ms`} />
        </div>
      ) : null}

      {/* ── Fleet table ── */}
      {result && (
        <div className="fade-in" style={{ border: "1px solid var(--color-rule)", overflowX: "auto" }}>
          {/* Header */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "2fr 80px 2fr 60px 100px 80px",
              padding: "8px 16px",
              background: "var(--color-ink-2)",
              borderBottom: "1px solid var(--color-rule)",
              minWidth: "600px",
            }}
          >
            {["DEVICE", "QRI", "ALGORITHM", "NIST", "COMPLIANCE", "TIME"].map((h) => (
              <span key={h} className="label">{h}</span>
            ))}
          </div>

          {result.results.map((r) => {
            const compliance = r.achieved_nist_level / 5;
            const compColor = compliance >= 0.8 ? "var(--color-green)" : compliance >= 0.6 ? "var(--color-yellow)" : "var(--color-red)";
            return (
              <div
                key={r.device}
                className="hover-surface"
                style={{
                  display: "grid",
                  gridTemplateColumns: "2fr 80px 2fr 60px 100px 80px",
                  padding: "12px 16px",
                  borderBottom: "1px solid var(--color-rule-dim)",
                  borderLeft: `2px solid ${tierColor(r.qri_tier)}`,
                  alignItems: "center",
                  transition: "background var(--fast) var(--ease)",
                  minWidth: "600px",
                }}
              >
                <div>
                  <div style={{ fontFamily: "var(--font-sans)", fontSize: "var(--text-13)", fontWeight: 500, color: "var(--color-fg-0)", marginBottom: 2 }}>
                    {r.device}
                  </div>
                  <TierTag tier={r.qri_tier} />
                </div>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-14)", fontWeight: 700, color: tierColor(r.qri_tier) }}>
                  {r.qri}
                </span>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-11)", color: "var(--color-fg-1)" }}>
                  {r.selected_algorithm}
                </span>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-13)", color: "var(--color-fg-0)" }}>
                  L{r.achieved_nist_level}
                  {r.security_gap > 0 && <span style={{ color: "var(--color-yellow)", marginLeft: 4 }}>⚠</span>}
                </span>
                <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                  <span className="label" style={{ color: compColor }}>{Math.round(compliance * 100)}%</span>
                  <Bar value={compliance} color={compColor} height={2} />
                </div>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-11)", color: "var(--color-fg-2)", textAlign: "right" }}>
                  {r.processing_time_ms.toFixed(1)}ms
                </span>
              </div>
            );
          })}
        </div>
      )}

      {!result && !loading && (
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            minHeight: 200,
            border: "1px solid var(--color-rule-dim)",
          }}
        >
          {activeTab === "preset" ? (
            <span className="label">SELECT ADVERSARY MODEL → RUN PRESENTS</span>
          ) : (
            <span className="label">UPLOAD EXCEL/CSV OR PASTE DATA → RUN SIMULATION</span>
          )}
        </div>
      )}

    </div>
  );
}

