import type { ClaimView } from "@/api";
import { Badge } from "@/components/ui/badge";

const SEVERITY_CLASS: Record<string, string> = {
  critical: "bg-red-500/20 text-red-300 hover:bg-red-500/25",
  high: "bg-orange-500/20 text-orange-300 hover:bg-orange-500/25",
  medium: "bg-yellow-500/20 text-yellow-300 hover:bg-yellow-500/25",
  low: "bg-blue-500/20 text-blue-300 hover:bg-blue-500/25",
  info: "bg-muted text-muted-foreground hover:bg-muted/80",
};

export default function ClaimsTable({ claims }: { claims: ClaimView[] }) {
  if (claims.length === 0) {
    return <p className="text-muted-foreground text-sm">No findings yet.</p>;
  }
  return (
    <ul className="space-y-1.5">
      {claims.map((c, i) => (
        <li
          key={i}
          className="flex items-center gap-3 px-2 py-1.5 rounded-md border bg-card text-sm"
        >
          <Badge
            className={`w-16 justify-center font-mono text-[10px] uppercase ${
              SEVERITY_CLASS[c.severity.toLowerCase()] ?? SEVERITY_CLASS.info
            }`}
          >
            {c.severity}
          </Badge>
          <span className="font-mono text-xs text-brand shrink-0">{c.vuln_class}</span>
          <span className="font-mono text-xs text-muted-foreground truncate flex-1">
            {c.url}
          </span>
          <span className="text-[10px] text-muted-foreground shrink-0">{c.status}</span>
        </li>
      ))}
    </ul>
  );
}
