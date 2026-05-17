# /mantis-report

Render an engagement's verified findings as a structured report.

```sh
mantis engagement report <engagement-id> --format markdown   # default
mantis engagement report <engagement-id> --format pdf
mantis engagement report <engagement-id> --format hackerone
mantis engagement report <engagement-id> --format bugcrowd
mantis engagement report <engagement-id> --format sarif
mantis engagement report <engagement-id> --format openvex
```

Ask the user which format. Default to markdown. Mention that every
report embeds Merkle inclusion proofs verifiable via:

```sh
mantis-verify --proof <file> --public-key <hex>
```
