import type { EngagementView } from "@/api";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

export default function EngagementList({ engagements }: { engagements: EngagementView[] }) {
  if (engagements.length === 0) {
    return (
      <p className="text-muted-foreground text-sm">
        No engagements yet. Start one with{" "}
        <code className="font-mono text-brand">mantis hack &lt;target&gt;</code>.
      </p>
    );
  }
  return (
    <ul className="space-y-2">
      {engagements.map((e) => (
        <li key={e.id}>
          <Card className="hover:border-brand/40 transition-colors py-0">
            <CardContent className="px-3 py-2">
              <div className="flex justify-between items-baseline gap-3">
                <span className="font-medium truncate">{e.name}</span>
                <span className="font-mono text-[10px] text-muted-foreground shrink-0">
                  {e.events} evts
                </span>
              </div>
              <div className="mt-1 flex items-center gap-2 text-xs">
                <StateBadge state={e.state} />
                <span className="font-mono text-muted-foreground/70 truncate">{e.id}</span>
              </div>
            </CardContent>
          </Card>
        </li>
      ))}
    </ul>
  );
}

function StateBadge({ state }: { state: string }) {
  // Map mantis engagement states onto shadcn badge variants where it
  // makes sense, otherwise use a custom class for the brand-green
  // active state.
  if (state === "active") {
    return (
      <Badge className="bg-brand/15 text-brand hover:bg-brand/20 font-mono text-[10px]">
        {state}
      </Badge>
    );
  }
  if (state === "paused") {
    return (
      <Badge className="bg-yellow-500/15 text-yellow-300 hover:bg-yellow-500/20 font-mono text-[10px]">
        {state}
      </Badge>
    );
  }
  const variant = state === "completed" ? "secondary" : "outline";
  return (
    <Badge variant={variant} className="font-mono text-[10px]">
      {state}
    </Badge>
  );
}
