---
name: mantis-report
description: Generate a disclosure-ready report for a Mantis engagement. Supports Markdown, PDF, HackerOne JSON, Bugcrowd JSON, SARIF, and OpenVEX.
trigger: "/mantis-report"
---

Render an engagement's verified findings as a structured report.

```sh
# Default markdown report:
mantis engagement report <engagement-id>

# Other formats:
mantis engagement report <engagement-id> --format pdf
mantis engagement report <engagement-id> --format hackerone
mantis engagement report <engagement-id> --format bugcrowd
mantis engagement report <engagement-id> --format sarif
mantis engagement report <engagement-id> --format openvex
```

Each report includes per-claim Merkle inclusion proofs that any
third party can verify with `mantis-verify --proof <file>
--public-key <workspace-hex-key>`.

Ask the user which format they want before generating. Default to
markdown if they don't specify.
