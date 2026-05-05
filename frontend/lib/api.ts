// lib/api.ts — typed fetch client for the PQC backend

import type {
  AnalyzeResponse,
  DeviceProfileRequest,
  ExplainResponse,
  FleetMetrics,
  HealthResponse,
  SimulateResponse,
} from "./types";

const BASE = process.env.NEXT_PUBLIC_API_URL;

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...init?.headers },
    ...init,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail ?? `HTTP ${res.status}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  health: () => apiFetch<HealthResponse>("/health"),

  analyze: (device: DeviceProfileRequest) =>
    apiFetch<AnalyzeResponse>("/analyze", {
      method: "POST",
      body: JSON.stringify(device),
    }),

  simulate: (devices: DeviceProfileRequest[]) =>
    apiFetch<SimulateResponse>("/simulate", {
      method: "POST",
      body: JSON.stringify({ devices }),
    }),

  explain: (device: DeviceProfileRequest) =>
    apiFetch<ExplainResponse>("/explain", {
      method: "POST",
      body: JSON.stringify(device),
    }),
};
