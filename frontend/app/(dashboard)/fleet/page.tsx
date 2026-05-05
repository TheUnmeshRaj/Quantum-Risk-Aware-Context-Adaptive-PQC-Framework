// app/(dashboard)/fleet/page.tsx
import { Topbar } from "@/components/layout/Topbar";
import { FleetContent } from "./FleetContent";

export default function FleetPage() {
  return (
    <>
      <Topbar title="Fleet" sub="Batch device evaluation · /simulate" />
      <main style={{ padding: "1rem", flex: 1 }}>
        <FleetContent />
      </main>
    </>
  );
}
