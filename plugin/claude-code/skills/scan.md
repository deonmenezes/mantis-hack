---
name: mantis-scan
description: Kick off a Mantis engagement against a target. Use when the user wants to scan a website, API endpoint, or asset they're authorized to test.
trigger: "/mantis-scan"
---

You are invoking the Mantis offensive-security daemon to start an
authorized engagement against a target.

**Before running, verify with the user:**
1. They have **explicit written authorization** to test the target.
2. The scope is well-defined (host, paths, ports).

**Then execute:**

```sh
# Start the daemon if it isn't already running:
mantis-daemon &

# Create and start an engagement:
mantis engagement create "$ENGAGEMENT_NAME" --target "$TARGET_URL"
mantis engagement start "$ENGAGEMENT_NAME"

# Watch live progress:
mantis engagement status "$ENGAGEMENT_NAME" --watch
```

Stream the output back to the user as it runs. Highlight verified
claims (Mantis only surfaces findings that survived independent
reproduction). When the engagement completes, offer to run
`/mantis-report` to render a disclosure-ready report.

**Refuse** to start a scan if the user cannot confirm authorization
or names a target they do not control / have not been authorized
against.
