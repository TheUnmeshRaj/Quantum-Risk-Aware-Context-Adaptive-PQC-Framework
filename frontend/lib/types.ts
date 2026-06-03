// lib/types.ts — canonical type definitions matching the FastAPI schema

export type QriTier = "LOW" | "MODERATE" | "ELEVATED" | "HIGH" | "CRITICAL";

export interface HardwareProfile {
  ram_kb: number;
  cpu: string;
  has_fpu: boolean;
  bandwidth_kbps: number;
}

export interface DeviceProfileRequest {
  name: string;
  description?: string;
  data_sensitivity: number;
  exposure_level: number;
  data_lifetime_yrs: number;
  threat_window: number;
  adversary: "low" | "medium" | "nation_state";
  hardware: HardwareProfile;
}

export interface AlgorithmAlternative {
  key: string;
  label: string;
  score: number;
  level: number;
}

export interface RejectedAlgorithm {
  algorithm: string;
  label: string;
  reason: string;
}

export interface ScoreBreakdown {
  security_fit: number;
  ram_fit: number;
  bandwidth_fit: number;
  penalty: number;
  final_score: number;
  required_level: number;
}

export interface ConstraintsSummary {
  ram_kb: number;
  has_fpu: boolean;
  bandwidth_kbps: number;
  capability_score: number;
}

export interface AnalyzeResponse {
  device: string;
  qri: number;
  qri_tier: QriTier;
  selected_algorithm: string;
  mode: string;
  security_level: string;
  score: number;
  required_nist_level: number;
  achieved_nist_level: number;
  security_gap: number;
  warning: string;
  reason: string;
  alternatives: AlgorithmAlternative[];
  rejected: RejectedAlgorithm[];
  constraints: ConstraintsSummary;
  breakdown: ScoreBreakdown;
  processing_time_ms: number;
  timestamp: number;
}

export interface FleetMetrics {
  device_count: number;
  avg_qri: number;
  max_qri: number;
  min_qri: number;
  critical_count: number;
  high_count: number;
  avg_compliance_score: number;
  total_processing_ms: number;
}

export interface SimulateResponse {
  results: AnalyzeResponse[];
  fleet_metrics: FleetMetrics;
}

export interface ExplainResponse {
  device: string;
  qri: number;
  required_level: number;
  step_by_step: string[];
  selected: string;
  selected_reason: string;
  alternatives: AlgorithmAlternative[];
  rejected: RejectedAlgorithm[];
  timestamp: number;
}

export interface HealthResponse {
  status: string;
  service: string;
  version: string;
  uptime_sec: number;
}

export interface DiscoveredDevice {
  ip: string;
  mac: string;
  profile: DeviceProfileRequest;
  analysis: AnalyzeResponse;
}

export interface DiscoverResponse {
  devices: DiscoveredDevice[];
  warning?: string;
}
