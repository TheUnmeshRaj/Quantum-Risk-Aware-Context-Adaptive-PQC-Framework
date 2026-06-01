import type { Metadata } from "next";
import { DiscoverContent } from "./DiscoverContent";

export const metadata: Metadata = {
  title: "Automated Device Discovery | UNYSIS",
  description: "Automate subnet service discovery and run context-adaptive post-quantum risk inference.",
};

export default function DiscoverPage() {
  return (
    <main className="flex-1 p-6 overflow-y-auto">
      <div style={{ borderBottom: "1px solid var(--color-rule)", paddingBottom: 16, marginBottom: 24 }}>
        <h1 style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-20)", fontWeight: 700, letterSpacing: "-0.01em", textTransform: "uppercase" }}>
          Automated Device Discovery
        </h1>
        <p style={{ fontFamily: "var(--font-sans)", fontSize: "var(--text-12)", color: "var(--color-fg-2)", marginTop: 4 }}>
          Auto-scan networks, identify firmware parameters, and run real-time post-quantum cryptography risk inference.
        </p>
      </div>
      <DiscoverContent />
    </main>
  );
}
