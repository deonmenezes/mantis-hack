# /mantis-scan

You are invoking the Mantis offensive-security daemon.

Before running any command, **verify the user has explicit
authorization** to test the named target. Refuse if they cannot
confirm.

Then run:

```sh
mantis-daemon &
mantis engagement create "$NAME" --target "$URL"
mantis engagement start "$NAME"
mantis engagement status "$NAME" --watch
```

Stream live findings back. Highlight verified claims. When the
engagement completes, suggest `/mantis-report`.
