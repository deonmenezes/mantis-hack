---
name: mantis-daemon
description: Start, stop, or check the Mantis daemon.
trigger: "/mantis-daemon"
---

Manage the local Mantis daemon process.

```sh
# Start:
mantis-daemon &

# Diagnostic check:
mantis doctor

# Stop (kill by pid found in ~/.Mantis/daemon.pid):
kill "$(cat ~/.Mantis/daemon.pid)"
```

`mantis doctor` validates:
- Workspace key is present and decryptable
- Event store opens cleanly
- Egress proxy can bind
- Configured LLM providers respond to a 1-token probe

Surface any failures it reports to the user with a remediation hint.
