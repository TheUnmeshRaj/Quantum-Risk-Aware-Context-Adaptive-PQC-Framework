"""
api/app.py
==========
Production FastAPI application — UNISYS PQC Decision Framework

Endpoints
---------
  GET  /health      → service health + uptime
  POST /analyze     → single device QRI + algorithm selection
  POST /simulate    → batch fleet evaluation
  POST /explain     → step-by-step decision explanation

Middleware
----------
  - CORS (localhost + configurable origins)
  - GZip compression (responses > 1 KB)
  - Request timing (X-Process-Time header on every response)

Error handling
--------------
  - HTTPException  → structured JSON with error_code + timestamp
  - All other      → 500 with same structure + server-side logging
"""

from __future__ import annotations

import json
import platform
import re
import shutil
import socket
import subprocess
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request  # type:ignore
from fastapi.middleware.cors import CORSMiddleware  # type:ignore
from fastapi.middleware.gzip import GZipMiddleware  # type:ignore
from fastapi.responses import JSONResponse, StreamingResponse  # type:ignore

from backend.core.decision_engine import (
    compute_capability_from_hardware,
    select_algorithm_scored,
)
from backend.core.network_discovery import (
    get_local_subnet,
    nmap,
    scan_arp_fast,
    scan_mdns,
    scan_nmap,
)
from backend.core.risk_engine import compute_qri, normalize_lifetime
from backend.models.schemas import (
    AlgorithmAlternative,
    AnalyzeResponse,
    ConstraintsSummary,
    DeviceProfileRequest,
    DiscoveredDevice,
    DiscoverRequest,
    DiscoverResponse,
    ExplainResponse,
    FleetMetrics,
    HealthResponse,
    RejectedAlgorithm,
    ScoreBreakdown,
    SimulateRequest,
    SimulateResponse,
)
from backend.simulation.evaluator import evaluate_fleet
from backend.utils.logger import get_logger

logger = get_logger(__name__)

_START_TIME = time.time()

# ── Application lifecycle ─────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("=" * 60)
    logger.info("  UNISYS PQC Framework API  —  starting up")
    logger.info("=" * 60)
    yield
    logger.info("UNISYS PQC Framework API  —  shutting down")


app = FastAPI(
    title="UNISYS — PQC Decision Framework",
    description=(
        "Quantum Risk-Aware Context-Adaptive Post-Quantum Cryptographic Decision API. "
        "Computes per-device Quantum Risk Index (QRI) and selects the optimal "
        "NIST-certified PQC algorithm given hardware constraints and adversary context."
    ),
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ── Middleware ────────────────────────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(GZipMiddleware, minimum_size=1000)


@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    t0 = time.time()
    response = await call_next(request)
    elapsed = round((time.time() - t0) * 1000, 2)
    response.headers["X-Process-Time-Ms"] = str(elapsed)
    logger.debug(
        "%s %s → %d  (%.2f ms)",
        request.method,
        request.url.path,
        response.status_code,
        elapsed,
    )
    return response


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    logger.warning("HTTP %d on %s: %s", exc.status_code, request.url.path, exc.detail)
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "detail": exc.detail,
            "error_code": f"ERR_{exc.status_code}",
            "timestamp": time.time(),
        },
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled exception on %s: %s", request.url.path, exc, exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error",
            "error_code": "ERR_500",
            "timestamp": time.time(),
        },
    )


# ── Internal helpers ──────────────────────────────────────────────────────────


def _build_analyze_response(dev: DeviceProfileRequest) -> AnalyzeResponse:
    """Run the full pipeline for one device and return a typed response."""
    hw_dict = {
        "ram_kb": dev.hardware.ram_kb,
        "cpu": dev.hardware.cpu,
        "has_fpu": dev.hardware.has_fpu,
        "bandwidth_kbps": dev.hardware.bandwidth_kbps,
    }
    cap = compute_capability_from_hardware(hw_dict)

    qri_out = compute_qri(
        data_sensitivity=dev.data_sensitivity,
        exposure_level=dev.exposure_level,
        data_lifetime=normalize_lifetime(dev.data_lifetime_yrs),
        threat_window=dev.threat_window,
        device_capability=cap,
    )

    dev_dict = dev.model_dump()
    decision = select_algorithm_scored(
        qri=qri_out["qri"],
        hardware=hw_dict,
        device=dev_dict,
    )

    return AnalyzeResponse(
        device=dev.name,
        qri=qri_out["qri"],
        qri_tier=qri_out["qri_tier"],
        selected_algorithm=decision.algorithm_key,
        mode=decision.algorithm_info.get("mode", ""),
        security_level=decision.algorithm_info.get("security_level", ""),
        score=decision.score,
        required_nist_level=decision.required_level,
        achieved_nist_level=decision.achieved_level,
        security_gap=decision.security_gap,
        warning=decision.warning,
        reason=decision.reason,
        alternatives=[AlgorithmAlternative(**a) for a in decision.alternatives],
        rejected=[RejectedAlgorithm(**r) for r in decision.rejected],
        constraints=ConstraintsSummary(
            ram_kb=dev.hardware.ram_kb,
            has_fpu=dev.hardware.has_fpu,
            bandwidth_kbps=dev.hardware.bandwidth_kbps,
            capability_score=cap,
        ),
        breakdown=ScoreBreakdown(**decision.breakdown),
        processing_time_ms=decision.processing_time_ms,
    )


def _iter_discovery_events(req: DiscoverRequest):
    """Yield discovery progress events so UI clients can render devices incrementally."""
    requested_subnets = [s.strip() for s in (req.subnets or "").split(",") if s.strip()]
    if not requested_subnets:
        default_subnet = get_local_subnet() or "192.168.1.0/24"
        requested_subnets = [default_subnet]

    seen_ips: set[str] = set()
    ip_mac_map: dict[str, str] = {}
    warnings: list[str] = []
    emitted_count = 0

    def build_generic_profile(
        host_ip: str, host_mac: str, host_name: str
    ) -> DeviceProfileRequest:
        return DeviceProfileRequest(
            name=host_name or f"Discovered Device {host_ip}",
            description=f"Discovered by ARP scan on {host_ip}",
            data_sensitivity=5.0,
            exposure_level=6.5,
            data_lifetime_yrs=5.0,
            threat_window=5.0,
            adversary="medium",
            hardware={
                "ram_kb": 512000,
                "cpu": host_name or "Unknown device",
                "has_fpu": False,
                "bandwidth_kbps": 100000.0,
            },
        )

    def emit_device(ip: str, mac: str, name: str):
        nonlocal emitted_count
        normalized_mac = (mac or "UNKNOWN").upper()
        dev_req = build_generic_profile(ip, normalized_mac, name)
        analysis = _build_analyze_response(dev_req)
        emitted_count += 1
        return {
            "type": "device",
            "device": DiscoveredDevice(
                ip=ip,
                mac=normalized_mac,
                profile=dev_req,
                analysis=analysis,
            ).model_dump(),
        }

    for subnet in requested_subnets:
        try:
            hosts = scan_arp_fast(subnet, timeout=1)
        except Exception as e:
            logger.warning("ARP scan failed for subnet %s: %s", subnet, e)
            hosts = []

        for host in hosts:
            ip = host.get("ip")
            mac = host.get("mac")
            name = host.get("hostname") or host.get("ip")
            if not ip or not mac:
                continue
            if ip in ("255.255.255.255", "127.0.0.1", "0.0.0.0") or ip.startswith(
                "224."
            ):
                continue
            if ip in seen_ips:
                continue
            seen_ips.add(ip)
            ip_mac_map[ip] = mac.upper()
            yield emit_device(ip, mac, name)

    try:
        mdns_hosts = scan_mdns(timeout=3.0)
    except Exception as e:
        logger.warning("mDNS scan failed: %s", e)
        mdns_hosts = []

    for mdns in mdns_hosts:
        for ip in mdns.get("addresses", []):
            if not ip or ip in seen_ips:
                continue
            if ip in ("255.255.255.255", "127.0.0.1", "0.0.0.0") or ip.startswith(
                "224."
            ):
                continue
            seen_ips.add(ip)
            mac = ip_mac_map.get(ip, "UNKNOWN")
            service_name = mdns.get("name") or mdns.get("server") or ip
            device_name = f"{service_name} ({mdns.get('service_type')})"
            yield emit_device(ip, mac, device_name)

    try:
        local_ip = "127.0.0.1"
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            local_ip = "127.0.0.1"

    if local_ip not in seen_ips:
        try:
            import uuid

            mac_num = uuid.getnode()
            mac_str = ":".join(re.findall(r"..", f"{mac_num:012X}")).upper()
        except Exception:
            mac_str = "00:00:00:00:00:00"

        host_dev_req = DeviceProfileRequest(
            name=f"Local Host ({platform.node()})",
            description="Local machine self-audit",
            data_sensitivity=6.5,
            exposure_level=4.0,
            data_lifetime_yrs=10.0,
            threat_window=5.0,
            adversary="medium",
            hardware={
                "ram_kb": 16000000,
                "cpu": platform.processor() or platform.machine(),
                "has_fpu": True,
                "bandwidth_kbps": 1000000.0,
            },
        )
        host_analysis = _build_analyze_response(host_dev_req)
        seen_ips.add(local_ip)
        emitted_count += 1
        yield {
            "type": "device",
            "device": DiscoveredDevice(
                ip=local_ip,
                mac=mac_str,
                profile=host_dev_req,
                analysis=host_analysis,
            ).model_dump(),
        }

    if req.scan_type == "nmap":
        if nmap is None:
            warnings.append("python-nmap is not installed on the backend.")
        if not shutil.which("nmap"):
            warnings.append("nmap binary is not installed or not available on PATH.")
        if warnings:
            yield {"type": "warning", "warning": "; ".join(warnings)}

        nmap_targets = []
        if req.targets:
            nmap_targets = [t.strip() for t in req.targets.split(",") if t.strip()]
        if not nmap_targets:
            nmap_targets = requested_subnets

        for target in nmap_targets:
            try:
                nmap_hosts = scan_nmap(target)
            except Exception as e:
                logger.warning("Nmap deep scan failed for target %s: %s", target, e)
                nmap_hosts = []

            for host in nmap_hosts:
                ip = host.get("ip")
                mac = host.get("mac") or "UNKNOWN"
                name = host.get("hostname") or host.get("ip")
                if not ip:
                    continue
                if ip in ("255.255.255.255", "127.0.0.1", "0.0.0.0") or ip.startswith(
                    "224."
                ):
                    continue
                if ip in seen_ips:
                    continue
                seen_ips.add(ip)
                ip_mac_map[ip] = mac.upper()
                service_info = host.get("service_details")
                device_name = f"{name} (nmap)"
                if isinstance(service_info, list) and service_info:
                    port_summary = ", ".join(
                        str(entry.get("port")) for entry in service_info[:3]
                    )
                    device_name = f"{name} [{port_summary}+]"
                yield emit_device(ip, mac, device_name)

    if emitted_count == 0:
        logger.info("ARP discovery returned no devices; returning an empty device list")

    yield {
        "type": "done",
        "warning": "; ".join(warnings) if warnings else None,
        "count": emitted_count,
    }


# ═══════════════════════════════════════════════════════════
# ENDPOINTS
# ═══════════════════════════════════════════════════════════


@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["Health"],
    summary="Service health check",
)
async def health_check() -> HealthResponse:
    """Returns service status, version, and uptime in seconds."""
    return HealthResponse(
        status="healthy",
        service="UNISYS PQC Decision Framework",
        version="2.0.0",
        uptime_sec=round(time.time() - _START_TIME, 1),
    )


@app.post(
    "/analyze",
    response_model=AnalyzeResponse,
    tags=["Decision Engine"],
    summary="Analyse a single device and select its PQC algorithm",
    responses={
        200: {"description": "QRI + algorithm selection with full explainability"},
        400: {"description": "Invalid device profile"},
        500: {"description": "Internal computation error"},
    },
)
async def analyze_device(device: DeviceProfileRequest) -> AnalyzeResponse:
    """
    Compute the Quantum Risk Index for a device and select the optimal
    NIST-certified PQC algorithm given its hardware constraints and adversary context.

    **Response includes:**
    - QRI score (0–100) and tier
    - Selected algorithm with scoring breakdown
    - Human-readable selection reason
    - Alternatives ranked by composite score
    - All rejected algorithms with explicit rejection reasons
    """
    logger.info("POST /analyze — device: %s", device.name)
    return _build_analyze_response(device)


@app.post(
    "/simulate",
    response_model=SimulateResponse,
    tags=["Simulation"],
    summary="Batch-evaluate a fleet of devices",
    responses={
        200: {"description": "Per-device decisions + fleet-level aggregate metrics"},
        400: {"description": "Invalid device list"},
    },
)
async def simulate_fleet(request: SimulateRequest) -> SimulateResponse:
    """
    Evaluate up to 50 devices in a single call.

    Returns per-device `AnalyzeResponse` objects **plus** fleet-level metrics:
    - Average / max / min QRI
    - Count of CRITICAL and HIGH risk devices
    - Mean NIST compliance score across the fleet
    - Total processing time
    """
    logger.info("POST /simulate — %d devices", len(request.devices))
    dev_dicts = [d.model_dump() for d in request.devices]
    _, fleet_metrics = evaluate_fleet(dev_dicts)

    results = [_build_analyze_response(d) for d in request.devices]

    return SimulateResponse(
        results=results,
        fleet_metrics=FleetMetrics(**fleet_metrics),
    )


@app.post(
    "/explain",
    response_model=ExplainResponse,
    tags=["Decision Engine"],
    summary="Step-by-step explanation of the decision logic for a device",
    responses={
        200: {"description": "Detailed decision walkthrough"},
        400: {"description": "Invalid device profile"},
    },
)
async def explain_decision(device: DeviceProfileRequest) -> ExplainResponse:
    """
    Returns a numbered, step-by-step walkthrough of *why* a specific algorithm
    was chosen — including the QRI derivation, required security level calculation,
    constraint filtering, and scoring for every candidate.
    """
    logger.info("POST /explain — device: %s", device.name)

    hw_dict = {
        "ram_kb": device.hardware.ram_kb,
        "cpu": device.hardware.cpu,
        "has_fpu": device.hardware.has_fpu,
        "bandwidth_kbps": device.hardware.bandwidth_kbps,
    }
    cap = compute_capability_from_hardware(hw_dict)

    qri_out = compute_qri(
        data_sensitivity=device.data_sensitivity,
        exposure_level=device.exposure_level,
        data_lifetime=normalize_lifetime(device.data_lifetime_yrs),
        threat_window=device.threat_window,
        device_capability=cap,
    )
    qri = qri_out["qri"]

    decision = select_algorithm_scored(
        qri=qri,
        hardware=hw_dict,
        device=device.model_dump(),
    )

    steps = [
        f"Step 1 - Risk Inputs: sensitivity={device.data_sensitivity}, "
        f"exposure={device.exposure_level}, lifetime={device.data_lifetime_yrs}yrs, "
        f"threat_window={device.threat_window}, adversary='{device.adversary}'.",
        f"Step 2 — Hardware Profile: RAM={device.hardware.ram_kb:,} KB, "
        f"CPU='{device.hardware.cpu}', FPU={'yes' if device.hardware.has_fpu else 'no'}, "
        f"Bandwidth={device.hardware.bandwidth_kbps:,} kbps -> "
        f"Capability score = {cap:.2f} / 10.",
        f"Step 3 — QRI Computation: weighted sum of 5 factors -> raw={qri_out['raw_score']}, "
        f"HNDL amplifier={'fired' if qri_out['amplified'] else 'not triggered'} -> "
        f"QRI = {qri} ({qri_out['qri_tier']}).",
        f"Step 4 — Required NIST Level: base={qri / 20:.2f} from QRI, "
        f"lifetime bump={'yes' if device.data_lifetime_yrs > 10 else 'no'}, "
        f"adversary bump ({'nation_state +1.5' if device.adversary == 'nation_state' else 'medium +0.5' if device.adversary == 'medium' else 'low +0'}) "
        f"-> required = L{decision.required_level:.2f}.",
        f"Step 5 — Constraint Filtering: {len(decision.rejected)} algorithm(s) eliminated "
        f"by hardware constraints (RAM / FPU checks).",
        f"Step 6 - Multi-Factor Scoring: remaining candidates scored on "
        f"security_fit (60%), ram_fit (25%), bandwidth_fit (15%). "
        f"Under-level candidates receive a 0.3x penalty.",
        f"Step 7 - Selection: '{decision.algorithm_key}' scored {decision.score:.4f} - "
        f"highest composite score among feasible candidates.",
        f"Step 8 - Gap Check: achieved NIST L{decision.achieved_level} vs required "
        f"L{decision.required_level:.2f} -> gap = {decision.security_gap:.2f} "
        + (
            "(WARNING: security gap exists)"
            if decision.security_gap > 0
            else "(no gap - fully compliant)."
        ),
    ]

    return ExplainResponse(
        device=device.name,
        qri=qri,
        required_level=decision.required_level,
        step_by_step=steps,
        selected=decision.algorithm_key,
        selected_reason=decision.reason,
        alternatives=[AlgorithmAlternative(**a) for a in decision.alternatives],
        rejected=[RejectedAlgorithm(**r) for r in decision.rejected],
    )


@app.get(
    "/",
    tags=["Health"],
    summary="Root status endpoint for health checks",
)
async def root_status():
    """Returns basic service index info for Render/Vercel status checks."""
    return {
        "status": "healthy",
        "service": "UNISYS PQC Decision Framework API",
        "version": "2.0.0",
        "docs": "/docs",
    }


@app.post(
    "/discover",
    response_model=DiscoverResponse,
    tags=["Simulation"],
    summary="Perform an ARP subnet scan and run PQC inference on discovered devices",
)
async def discover_network(req: DiscoverRequest) -> DiscoverResponse:
    """
    Performs a real ARP sweep on the requested subnet(s) and returns all
    reachable devices by IP/MAC along with a generic PQC analysis.
    """
    logger.info(
        "POST /discover — subnets: %s, speed: %s, scan_type: %s",
        req.subnets,
        req.speed,
        req.scan_type,
    )

    discovered_hosts: list[DiscoveredDevice] = []
    warning: str | None = None

    for event in _iter_discovery_events(req):
        event_type = event.get("type")
        if event_type == "device":
            discovered_hosts.append(DiscoveredDevice(**event["device"]))
        elif event_type in {"warning", "done"} and event.get("warning"):
            warning = str(event["warning"])

    return DiscoverResponse(devices=discovered_hosts, warning=warning)


@app.post(
    "/discover/stream",
    tags=["Simulation"],
    summary="Stream discovered devices as soon as they are found",
)
async def discover_network_stream(req: DiscoverRequest):
    logger.info(
        "POST /discover/stream — subnets: %s, speed: %s, scan_type: %s",
        req.subnets,
        req.speed,
        req.scan_type,
    )

    def event_stream():
        for event in _iter_discovery_events(req):
            yield json.dumps(event) + "\n"

    return StreamingResponse(
        event_stream(),
        media_type="application/x-ndjson",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
