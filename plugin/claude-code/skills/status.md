---
name: mantis-status
description: Show the current state of one or all Mantis engagements — claims found, request budget, scope, active experiments.
trigger: "/mantis-status"
---

Show engagement status from the local Mantis daemon.

```sh
# All engagements:
mantis engagement status

# Single engagement (replace ID):
mantis engagement status <engagement-id>
```

Render the output as a compact summary:
- Engagement ID, name, state
- Verified / rejected / retained claims
- Request budget remaining
- Last activity timestamp

If the daemon is not running, prompt the user to run
`mantis-daemon` or `/mantis-daemon` first.
