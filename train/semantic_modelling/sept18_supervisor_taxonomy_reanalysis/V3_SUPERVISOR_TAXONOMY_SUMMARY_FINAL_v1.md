# V3 Semantic Root-Cause Re-analysis — Final Summary

This analysis follows the supervisor's revised taxonomy and reviews all 39 TRAIN cases.

## Final outcome

- 39/39 cases reviewed using: (a) actual vulnerability mechanism, (b) generated CodeQL security property, and (c) concrete mismatch.
- 38/39 cases receive one of the five supervisor semantic categories.
- 1/39 case (CVE-2022-27047) is retained as a semantically aligned strict-success control with no semantic failure root cause.

## Semantic taxonomy

- **Wrong vulnerability mechanism:** 9/38 (23.7%)
- **Incomplete vulnerability mechanism:** 4/38 (10.5%)
- **Missing validation semantics:** 7/38 (18.4%)
- **Missing relational/contextual semantics:** 11/38 (28.9%)
- **Insufficient evidence / unclear:** 7/38 (18.4%)

## Same-CWE generic-template hypothesis

The outputs are consistent with semantic over-generalization / template collapse within a CWE. This conclusion does not follow merely from reuse of one CWE-level query, because that is part of the experimental design. The evidence is that heterogeneous actual mechanisms are repeatedly represented by one generic query abstraction that mismatches them.

- **CWE-116:** template `untrusted input -> generic output/filesystem`; supported=7, aligned=0, undetermined=0.
- **CWE-284:** template `web endpoint -> sensitive operation, with no explicit authorization evidence`; supported=12, aligned=0, undetermined=2.
- **CWE-434:** template `request/upload filename -> filesystem write or move`; supported=5, aligned=1, undetermined=5.
- **CWE-639:** template `user-controlled ID -> ID-like resource access/modification parameter`; supported=7, aligned=0, undetermined=0.

## Strict-success validity finding

CVE-2023-43668 is the strongest cautionary case: it achieved 446 vulnerable hits and 0 patched hits, but the generated query models generic IDOR-style identifier flow whereas the actual mechanism is sensitive JDBC parameter-key filtering. Therefore strict hit-based success does not necessarily imply semantic correctness.

## Research implication

After compilation was repaired, the remaining bottleneck is not primarily CodeQL syntax/API compatibility. The dominant failures are semantic: relational/contextual semantics, wrong vulnerability mechanisms, missing validation semantics, and incomplete mechanism modelling.

A plausible next research direction is therefore to prevent a single CWE label from driving one generic vulnerability template, and instead make the agent identify the concrete mechanism, security relation, validation boundary, and application-specific context before translating that mechanism into CodeQL.
