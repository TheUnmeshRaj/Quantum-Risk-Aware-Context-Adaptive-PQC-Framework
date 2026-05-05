// app/(dashboard)/analyze/page.tsx
import { Topbar } from "@/components/layout/Topbar";
import { AnalyzeContent } from "./AnalyzeContent";

export default function AnalyzePage() {
  return (
    <>
      <Topbar title="Analyze" sub="Single device QRI + algorithm selection" />
      <main className="flex-1 pt-6 pr-6 pb-6 pl-4">
        <AnalyzeContent />
      </main>
    </>
  );
}
