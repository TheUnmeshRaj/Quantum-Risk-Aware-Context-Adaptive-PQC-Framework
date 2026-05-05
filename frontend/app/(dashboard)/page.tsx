// app/(dashboard)/page.tsx — Overview
import { Topbar } from "@/components/layout/Topbar";
import { OverviewContent } from "./OverviewContent";

export default function OverviewPage() {
  return (
    <>
      <Topbar title="Overview" sub="PQC Framework Status" />
      <main className="flex-1 pt-6 pr-6 pb-6 pl-4">
        <OverviewContent />
      </main>
    </>
  );
}
