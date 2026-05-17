---
name: mantis-claim
description: Inspect a specific verified claim — its evidence chain, reproducer scripts, CVSS, and Merkle inclusion proof.
trigger: "/mantis-claim"
---

Pull details for a single claim discovered by Mantis.

```sh
mantis claim <claim-id>
```

The output includes:
- Vulnerability class + primitive id
- Surface (URL/host/port)
- Severity and CVSS v4 score
- Posterior probability + verifier id
- Evidence items (with Merkle inclusion proofs)
- Reproducer scripts (cURL / raw HTTP / Python / Burp)

Offer to export the reproducer in any of the supported formats:

```sh
mantis exploit <claim-id> --format python
mantis exploit <claim-id> --format curl
```
