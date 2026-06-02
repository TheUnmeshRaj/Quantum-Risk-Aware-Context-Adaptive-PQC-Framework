// app/(dashboard)/discover/page.tsx
import { Topbar } from "@/components/layout/Topbar";
import { DiscoverContent } from "./DiscoverContent";

export const metadata = {
  title: "Discover | UNISYS",
  description: "Automate subnet service discovery and run context-adaptive post-quantum risk inference.",
};

export default function DiscoverPage() {
  return (
    <>
      <Topbar title="Discover" sub="Automated network service scanning and PQC inference" />
      <main style={{ padding: "1rem", flex: 1, overflowY: "auto" }}>
        <DiscoverContent />
      </main>
    </>
  );
}
