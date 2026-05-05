// lib/fixtures.ts — default device profiles for demo usage

import type { DeviceProfileRequest } from "./types";

export const DEVICE_PROFILES: DeviceProfileRequest[] = [
  {
    name: "IoT Temperature Sensor",
    data_sensitivity: 3.0,
    exposure_level: 7.0,
    data_lifetime_yrs: 10,
    threat_window: 5.0,
    adversary: "medium",
    hardware: { ram_kb: 64, cpu: "ARM Cortex-M0+", has_fpu: false, bandwidth_kbps: 50 },
  },
  {
    name: "Developer Workstation",
    data_sensitivity: 6.5,
    exposure_level: 5.0,
    data_lifetime_yrs: 5,
    threat_window: 6.0,
    adversary: "medium",
    hardware: { ram_kb: 32768000, cpu: "x86-64 Intel i9", has_fpu: true, bandwidth_kbps: 1000000 },
  },
  {
    name: "Public API Server",
    data_sensitivity: 7.0,
    exposure_level: 9.0,
    data_lifetime_yrs: 7,
    threat_window: 7.5,
    adversary: "nation_state",
    hardware: { ram_kb: 8192000, cpu: "x86-64 Xeon", has_fpu: true, bandwidth_kbps: 10000000 },
  },
  {
    name: "Hospital Patient Records DB",
    data_sensitivity: 9.5,
    exposure_level: 5.0,
    data_lifetime_yrs: 25,
    threat_window: 9.5,
    adversary: "nation_state",
    hardware: { ram_kb: 128000000, cpu: "x86-64 server", has_fpu: true, bandwidth_kbps: 10000000 },
  },
  {
    name: "Industrial PLC Controller",
    data_sensitivity: 8.5,
    exposure_level: 4.0,
    data_lifetime_yrs: 20,
    threat_window: 8.5,
    adversary: "nation_state",
    hardware: { ram_kb: 512000, cpu: "ARM Cortex-A53", has_fpu: true, bandwidth_kbps: 100000 },
  },
  {
    name: "Smart Home Hub",
    data_sensitivity: 4.0,
    exposure_level: 6.0,
    data_lifetime_yrs: 8,
    threat_window: 5.0,
    adversary: "medium",
    hardware: { ram_kb: 512000, cpu: "ARM Cortex-A7", has_fpu: false, bandwidth_kbps: 10000 },
  },
];
