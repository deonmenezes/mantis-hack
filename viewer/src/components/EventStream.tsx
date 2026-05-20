import { useEffect, useRef } from "react";
import { ScrollArea } from "@/components/ui/scroll-area";

export default function EventStream({ lines }: { lines: string[] }) {
  const rootRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom when new lines arrive, unless the user has
  // scrolled up — then leave the viewport alone. The shadcn ScrollArea
  // doesn't expose a viewport ref directly, so we grab it from the
  // Radix `data-slot` attribute.
  useEffect(() => {
    const root = rootRef.current;
    if (!root) return;
    const vp = root.querySelector<HTMLDivElement>(
      '[data-slot="scroll-area-viewport"]'
    );
    if (!vp) return;
    const nearBottom = vp.scrollHeight - vp.scrollTop - vp.clientHeight < 100;
    if (nearBottom) vp.scrollTop = vp.scrollHeight;
  }, [lines]);

  return (
    <div ref={rootRef} className="flex-1 overflow-hidden">
      <ScrollArea className="h-full px-4 pb-4">
        <div className="font-mono text-xs leading-relaxed text-foreground/80">
          {lines.length === 0 ? (
            <div className="text-muted-foreground">Waiting for daemon activity…</div>
          ) : (
            lines.map((line, i) => (
              <div key={i} className="whitespace-pre-wrap break-all">
                <span className="text-muted-foreground/60 mr-2 select-none">
                  {String(i + 1).padStart(4, "0")}
                </span>
                {line}
              </div>
            ))
          )}
        </div>
      </ScrollArea>
    </div>
  );
}
