// app/(dashboard)/analyze/page.tsx
import { Topbar } from "@/components/layout/Topbar";
import { AnalyzeContent } from "./AnalyzeContent";

export default function AnalyzePage() {
  return (
    <>
      <Topbar title="Analyze" sub="Single device QRI + algorithm selection" />
      <main style={{ padding: "1rem", flex: 1 }}>
        <AnalyzeContent />
      </main>
    </>
  );
}
