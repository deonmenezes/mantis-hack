# /mantis-claim

Show details for a single Mantis claim.

```sh
mantis claim <claim-id>
mantis exploit <claim-id> --format python   # or curl, raw-http, burp
```

Surface: vuln class, primitive id, severity, CVSS v4, posterior
probability, evidence items (with Merkle proofs), reproducer
scripts in the format the user chooses.
