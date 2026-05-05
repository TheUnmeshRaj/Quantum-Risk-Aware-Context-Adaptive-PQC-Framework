// app/(dashboard)/fleet/page.tsx
import { Topbar } from "@/components/layout/Topbar";
import { FleetContent } from "./FleetContent";

export default function FleetPage() {
  return (
    <>
      <Topbar title="Fleet" sub="Batch device evaluation · /simulate" />
      <main className="flex-1 pt-6 pr-6 pb-6 pl-4">
        <FleetContent />
      </main>
    </>
  );
}
