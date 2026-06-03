// lib/api.ts — typed fetch client for the PQC backend

import type {
  AnalyzeResponse,
  DeviceProfileRequest,
  DiscoveredDevice,
  DiscoverResponse,
  ExplainResponse,
  FleetMetrics,
  HealthResponse,
  SimulateResponse,
} from "./types";

let BASE = process.env.NEXT_PUBLIC_API_URL?.replace(/\/$/, "") || "";

// Smart client-side runtime fallback / proxy switcher
if (typeof window !== "undefined") {
  const hostname = window.location.hostname;
  if (hostname === "localhost" || hostname === "127.0.0.1") {
    // Local development:
    // If NEXT_PUBLIC_API_URL is configured to hit the online Render backend,
    // route requests through the local /api rewrite proxy to avoid local browser CORS blocks,
    // security extensions, and secure DNS lookup restrictions.
    if (BASE.includes("pqc-framwork.onrender.com")) {
      BASE = "/api";
    } else if (!BASE) {
      BASE = "http://localhost:8000";
    }
  } else {
    // Production (e.g. Vercel deployment): route requests through the /api rewrite proxy
    // to bypass browser CORS preflight restrictions, mixed content, and DNS lookup blocks.
    BASE = "/api";
  }
} else {
  // Server-side (SSG/SSR) rendering: default to the live Render backend URL if not configured
  if (!BASE) {
    BASE = "https://pqc-framwork.onrender.com";
  }
}

type DiscoverStreamEvent =
  | { type: "device"; device: DiscoveredDevice }
  | { type: "warning"; warning: string }
  | { type: "done"; warning?: string | null; count?: number };

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const finalUrl = `${BASE}${path}`;
  console.log(`[UNISYS API] Initiating fetch request:`, {
    path,
    configuredBase: process.env.NEXT_PUBLIC_API_URL,
    resolvedBase: BASE,
    finalUrl,
    method: init?.method ?? "GET",
    timestamp: new Date().toISOString(),
  });

  try {
    const res = await fetch(finalUrl, {
      headers: { "Content-Type": "application/json", ...init?.headers },
      ...init,
    });

    console.log(`[UNISYS API] Response received from ${path}:`, {
      status: res.status,
      statusText: res.statusText,
      ok: res.ok,
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      const errorMsg = err.detail ?? `HTTP ${res.status}`;
      console.error(
        `[UNISYS API] Server returned error for ${path}:`,
        errorMsg,
      );
      throw new Error(errorMsg);
    }
    return res.json() as Promise<T>;
  } catch (err: any) {
    console.error(`[UNISYS API] Fetch exception caught on ${path}:`, {
      name: err?.name,
      message: err?.message,
      stack: err?.stack,
      url: finalUrl,
      help: "If this says 'Failed to fetch', check: 1) Is the backend awake? 2) Is there a CORS policy block? 3) Is there an insecure HTTP mixed content block?",
    });
    throw err;
  }
}

async function discoverStream(
  options?: {
    subnets?: string;
    speed?: string;
    scan_type?: string;
    targets?: string;
  },
  handlers?: {
    onDevice?: (device: DiscoveredDevice) => void;
    onWarning?: (warning: string) => void;
  },
): Promise<DiscoverResponse> {
  const path = "/discover/stream";
  const finalUrl = `${BASE}${path}`;

  const res = await fetch(finalUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(options || {}),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail ?? `HTTP ${res.status}`);
  }

  if (!res.body) {
    const fallback = await apiFetch<DiscoverResponse>("/discover", {
      method: "POST",
      body: JSON.stringify(options || {}),
    });
    if (fallback.warning) {
      handlers?.onWarning?.(fallback.warning);
    }
    fallback.devices.forEach((device) => handlers?.onDevice?.(device));
    return fallback;
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  const devices: DiscoveredDevice[] = [];
  let warning: string | undefined;
  let buffer = "";

  while (true) {
    const { done, value } = await reader.read();
    buffer += decoder.decode(value || new Uint8Array(), { stream: !done });

    let newlineIndex = buffer.indexOf("\n");
    while (newlineIndex >= 0) {
      const line = buffer.slice(0, newlineIndex).trim();
      buffer = buffer.slice(newlineIndex + 1);

      if (line) {
        const event = JSON.parse(line) as DiscoverStreamEvent;
        if (event.type === "device") {
          devices.push(event.device);
          handlers?.onDevice?.(event.device);
        } else if (event.type === "warning" && event.warning) {
          warning = event.warning;
          handlers?.onWarning?.(event.warning);
        } else if (event.type === "done" && event.warning) {
          warning = event.warning;
          handlers?.onWarning?.(event.warning);
        }
      }

      newlineIndex = buffer.indexOf("\n");
    }

    if (done) {
      const trailing = buffer.trim();
      if (trailing) {
        const event = JSON.parse(trailing) as DiscoverStreamEvent;
        if (event.type === "device") {
          devices.push(event.device);
          handlers?.onDevice?.(event.device);
        } else if (
          (event.type === "warning" || event.type === "done") &&
          event.warning
        ) {
          warning = event.warning;
          handlers?.onWarning?.(event.warning);
        }
      }
      break;
    }
  }

  return { devices, warning };
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

  discover: (options?: {
    subnets?: string;
    speed?: string;
    scan_type?: string;
    targets?: string;
  }) =>
    apiFetch<DiscoverResponse>("/discover", {
      method: "POST",
      body: JSON.stringify(options || {}),
    }),

  discoverStream,
};
