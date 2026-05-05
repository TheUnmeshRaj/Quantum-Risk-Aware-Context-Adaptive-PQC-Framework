// app/(dashboard)/page.tsx — Overview
import { Topbar } from "@/components/layout/Topbar";
import { OverviewContent } from "./OverviewContent";

export default function OverviewPage() {
  return (
    <>
      <Topbar title="Overview" sub="PQC Framework Status" />
      <main style={{ padding: 24, flex: 1 }}>
        <OverviewContent />
      </main>
    </>
  );
}
