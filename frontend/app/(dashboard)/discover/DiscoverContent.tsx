"use client";

import { NetworkDiscoveryCard } from "@/components/dashboard/NetworkDiscoveryCard";

export function DiscoverContent() {
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        gap: 24,
        maxWidth: 1100,
      }}
    >
      <NetworkDiscoveryCard />
    </div>
  );
}
