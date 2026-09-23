Dear Professor Kang,

I re-analysed all 39 V3 cases using the revised root-cause categories you suggested.

For every case, I explicitly recorded: (a) the actual vulnerability mechanism, (b) the security property modeled by the generated CodeQL query, and (c) the concrete mismatch between them.

Among the 38 cases that required a semantic category, the final distribution is:
- Wrong vulnerability mechanism: 9/38 (23.7%)
- Incomplete vulnerability mechanism: 4/38 (10.5%)
- Missing validation semantics: 7/38 (18.4%)
- Missing relational/contextual semantics: 11/38 (28.9%)
- Insufficient evidence / unclear: 7/38 (18.4%)

One strict-success case, CVE-2022-27047, appears semantically aligned and is retained as a positive control.

The same-CWE generic-template hypothesis is also supported by the outputs. For example, CWE-284 uses one 'web endpoint -> sensitive operation without explicit authorization' abstraction, although the actual vulnerabilities include SAML/OIDC audience validation, remoting trust boundaries, servlet filter/context-path behavior, credential lookup scope, protocol-session policy, and execution-context propagation.

Importantly, I found one strict metric success that is semantically wrong: CVE-2023-43668 produced 446 vulnerable hits and 0 patched hits, but the generated query modeled IDOR-style identifier flow, while the actual patch concerned sensitive JDBC parameter-key filtering.

So the current evidence suggests that, after compilation is fixed, the main bottleneck is semantic modelling rather than CodeQL API compatibility. A possible next step is to make the agent identify the concrete vulnerability mechanism and security relation before generating the CWE-level CodeQL abstraction.

I have prepared the updated one-row-per-case spreadsheet and a summary of the results.

Best regards,
Shirui
