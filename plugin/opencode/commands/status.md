# /mantis-status

Show engagement status from the local Mantis daemon.

```sh
mantis engagement status            # all engagements
mantis engagement status <id>       # specific engagement
```

Format the output as a compact table: ID, name, state, verified
claims, request budget remaining, last-activity timestamp.

If the daemon is not running, prompt the user to start it with
`mantis-daemon &`.
