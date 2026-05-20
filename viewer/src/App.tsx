import { useEffect, useState } from "react";
import { fetchState, subscribeEvents, type WebState, type WireEvent } from "@/api";
import EngagementList from "@/components/EngagementList";
import ClaimsTable from "@/components/ClaimsTable";
import EventStream from "@/components/EventStream";
import { ScrollArea } from "@/components/ui/scroll-area";

type Connection = "connecting" | "live" | "down";

const MAX_LOG_LINES = 500;

export default function App() {
  const [state, setState] = useState<WebState | null>(null);
  const [connection, setConnection] = useState<Connection>("connecting");
  const [log, setLog] = useState<string[]>([]);

  useEffect(() => {
    let mounted = true;

    fetchState()
      .then((s) => {
        if (!mounted) return;
        setState(s);
        setLog(s.log_tail);
        setConnection("live");
      })
      .catch(() => mounted && setConnection("down"));

    const es = subscribeEvents((e) => applyEvent(e, setState, setLog));
    es.onerror = () => setConnection("down");
    es.onopen = () => setConnection("live");

    return () => {
      mounted = false;
      es.close();
    };
  }, []);

  return (
    <div className="h-full flex flex-col bg-background text-foreground">
      <Header connection={connection} engagementCount={state?.engagements.length ?? 0} />
      <main className="flex-1 grid grid-cols-12 gap-px bg-border overflow-hidden">
        <aside className="col-span-4 bg-background overflow-hidden flex flex-col">
          <ScrollArea className="flex-1 px-4 py-4">
            <SectionTitle>Engagements</SectionTitle>
            <EngagementList engagements={state?.engagements ?? []} />
            <div className="mt-8">
              <SectionTitle>Findings</SectionTitle>
              <ClaimsTable claims={state?.claims ?? []} />
            </div>
          </ScrollArea>
        </aside>
        <section className="col-span-8 bg-background overflow-hidden flex flex-col">
          <div className="px-4 pt-4">
            <SectionTitle>Live event stream</SectionTitle>
          </div>
          <EventStream lines={log} />
        </section>
      </main>
    </div>
  );
}

function applyEvent(
  e: WireEvent,
  setState: React.Dispatch<React.SetStateAction<WebState | null>>,
  setLog: React.Dispatch<React.SetStateAction<string[]>>
) {
  setState((prev) => {
    if (!prev) return prev;
    switch (e.type) {
      case "EngagementUpserted": {
        const others = prev.engagements.filter((x) => x.id !== e.id);
        return {
          ...prev,
          engagements: [
            ...others,
            { id: e.id, name: e.name, state: e.state, events: e.events },
          ],
        };
      }
      case "ClaimAdded":
        return {
          ...prev,
          claims: [
            { vuln_class: e.vuln_class, severity: e.severity, status: e.status, url: e.url },
            ...prev.claims,
          ],
        };
      case "TimelineMarkAdded":
        return {
          ...prev,
          timeline: [
            ...prev.timeline,
            { unix_seconds: e.unix_seconds, label: e.label, kind: e.kind },
          ],
        };
      case "McTreeUpdated":
        return { ...prev, mcts_tree: { root: e.root, iterations: e.iterations } };
      case "LogLine":
        return prev;
    }
  });

  if (e.type === "LogLine") {
    setLog((prev) => {
      const next = [...prev, e.line];
      if (next.length > MAX_LOG_LINES) next.splice(0, next.length - MAX_LOG_LINES);
      return next;
    });
  }
}

function Header({
  connection,
  engagementCount,
}: {
  connection: Connection;
  engagementCount: number;
}) {
  const dotClass =
    connection === "live"
      ? "bg-brand shadow-[0_0_8px_var(--tw-shadow-color)] shadow-brand"
      : connection === "connecting"
      ? "bg-yellow-400"
      : "bg-destructive";
  return (
    <header className="flex items-center justify-between border-b px-6 py-3">
      <div className="flex items-center gap-3">
        <span className="font-mono text-brand text-lg font-semibold tracking-tight">
          mantis
        </span>
        <span className="text-muted-foreground text-xs">viewer</span>
      </div>
      <div className="flex items-center gap-6 text-xs text-muted-foreground">
        <span className="font-mono">
          {engagementCount} engagement{engagementCount === 1 ? "" : "s"}
        </span>
        <span className="flex items-center gap-2">
          <span className={`inline-block w-2 h-2 rounded-full ${dotClass}`} />
          <span>
            {connection === "live"
              ? "daemon: live"
              : connection === "connecting"
              ? "connecting…"
              : "daemon: down"}
          </span>
        </span>
      </div>
    </header>
  );
}

function SectionTitle({ children }: { children: React.ReactNode }) {
  return (
    <h2 className="text-[10px] uppercase tracking-widest text-muted-foreground mb-3 font-mono">
      {children}
    </h2>
  );
}
