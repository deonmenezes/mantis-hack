// Typed client for the mantis-daemon web UI.
//
// These types mirror `crates/mantis-web-ui/src/state.rs`. They are
// hand-maintained for now; a future iteration will codegen them from
// the Rust source via `ts-rs` or `specta`.

export interface EngagementView {
  id: string;
  name: string;
  state: string;
  events: number;
}

export interface ClaimView {
  vuln_class: string;
  severity: string;
  status: string;
  url: string;
}

export interface TimelineMark {
  unix_seconds: number;
  label: string;
  kind: string;
}

export interface McNode {
  id: string;
  label: string;
  ucb1: number;
  visits: number;
  posterior: number;
  children: McNode[];
}

export interface McTreeView {
  root: McNode;
  iterations: number;
}

export interface WebState {
  engagements: EngagementView[];
  claims: ClaimView[];
  log_tail: string[];
  mcts_tree: McTreeView | null;
  timeline: TimelineMark[];
}

export type WireEvent =
  | { type: "EngagementUpserted"; id: string; name: string; state: string; events: number }
  | { type: "ClaimAdded"; vuln_class: string; severity: string; status: string; url: string }
  | { type: "LogLine"; line: string }
  | { type: "McTreeUpdated"; root: McNode; iterations: number }
  | { type: "TimelineMarkAdded"; unix_seconds: number; label: string; kind: string };

export async function fetchState(): Promise<WebState> {
  const r = await fetch("/api/state");
  if (!r.ok) throw new Error(`/api/state -> ${r.status}`);
  return (await r.json()) as WebState;
}

// SSE subscription helper. Returns an EventSource the caller closes
// when unmounting. Each `message` event is a JSON-encoded WireEvent.
export function subscribeEvents(onEvent: (e: WireEvent) => void): EventSource {
  const es = new EventSource("/api/events");
  es.onmessage = (msg) => {
    try {
      onEvent(JSON.parse(msg.data) as WireEvent);
    } catch (err) {
      console.error("bad SSE payload", err, msg.data);
    }
  };
  return es;
}
