# Stage16 C-Level Reproducibility Audit v1

## Scope

Read-only audit of the apparent C-level compilation change from the original Stage16 result to the fresh C-level four-arm experiment.

- TRAIN only
- TEST access forbidden
- No model execution
- No CodeQL rerun
- No database reconstruction
- No manual query editing

## 1. Apparent 47.5% -> 0% drop

The original C-level compilation result was:

- 114 / 240 = 47.5%

However, the new four-arm experiment uses only four CWEs:

- CWE-116: 7 pairs
- CWE-284: 14 pairs
- CWE-434: 11 pairs
- CWE-639: 7 pairs
- Total: 39 pairs

Restricting the original frozen C results to exactly these 39 pairs gives:

- CWE-116: 7 / 7 compiled
- CWE-284: 0 / 14 compiled
- CWE-434: 0 / 11 compiled
- CWE-639: 0 / 7 compiled
- Total: 7 / 39 = 17.95%

Therefore, most of the apparent 47.5% -> 0% difference is explained by the selected 39-pair subset being substantially harder than the complete 240-pair TRAIN set.

## 2. Remaining 7/39 -> 0/39 difference

The remaining difference is entirely attributable to CWE-116.

Historical C initial:

- compiled: 7 / 7
- query SHA256:
  `5e6a8afbb75fab00d8f2e21e474cf8bcdafa9ee028890dc2e7c1c0094b16f6f3`

Fresh shared C initial:

- compiled: 0 / 7
- query SHA256:
  `871a9491c20ece18c6f8d0d1ba2f5fa06b9f716f34fd7afa995dfef608790d56`

The two runs therefore did not evaluate the same generated query.

## 3. Cause of fresh CWE-116 compilation failure

The fresh query contains genuine CodeQL compilation errors, including:

- unresolved `MethodAccess`
- invalid `hasQualifiedName(string, string)` usage
- unresolved member API calls
- multiple conflicting `select` clauses
- invalid `union`
- syntax error near the final closing brace

Thus the fresh 0/7 result is caused by the newly generated query rather than by nondeterministic behaviour of the frozen CodeQL databases.

## 4. C-level generation trajectory difference

Both runs were nominally evidence level C:

- A: historical advisory
- B: frozen Java patch evidence
- C: bounded vulnerable-source exploration

However, the actual trajectories differed.

The historical CWE-116 C run actively used bounded vulnerable-source exploration before producing its initial query.

The fresh shared C initial generation retained the C source tools but recorded:

- C source events: 0

Therefore, evidence availability was nominally C in both cases, but the agent did not follow the same source-exploration trajectory.

## 5. Interpretation

The apparent compilation change should be decomposed as:

- 47.5% -> 17.95%: sample-selection effect
- 17.95% -> 0%: generation/protocol variance concentrated in CWE-116

This is not evidence that the frozen CodeQL databases failed to reproduce historical query behaviour.

## 6. Clarification on the previous 39/39 experiment

The earlier four-arm experiment that achieved 39/39 compilation used an A-level shared initial, not a C-level shared initial.

That result therefore demonstrated compilation repair effectiveness from the A-level initial condition and should not be interpreted as showing that C-level initial compilation had already reached 100%.

## 7. Current fresh-C four-arm outcome

Across the 39 TRAIN pairs:

- V0 Compiler Feedback: final 0/39, best 0/39
- V1 Library-Aware Reasoning: final 7/39, best 7/39
- V2 Auto Skill Retrieval: final 7/39, best 7/39
- V3 Library + Auto Skill: final 0/39, best 7/39
- Strict success: 0/39 for all arms

Only CWE-116 achieved compilation recovery.

## Conclusion

The reproducibility audit supports the interpretation that the apparent C-level compilation drop is explained by a combination of:

1. a harder selected subset, and
2. fresh-generation / protocol trajectory variance.

TEST remained untouched throughout the audit.
