// components/ui/Skeleton.tsx
export function Skel({ w, h }: { w?: string | number; h?: string | number }) {
  return (
    <div
      className="skeleton"
      style={{ width: w ?? "100%", height: h ?? 12 }}
    />
  );
}
