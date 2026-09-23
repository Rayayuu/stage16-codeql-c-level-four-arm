# Mechanism-First Semantic Modelling Pilot — CWE-639

## Research question

Can mechanism-first semantic planning reduce within-CWE generic-template over-generalization and improve semantic alignment while preserving compilation success?

## Experimental comparison

Two matched TRAIN-only arms were evaluated:

- **M0 — CWE-first control:** generic CWE-level planning followed by one CWE-level CodeQL query.
- **M1 — mechanism-first:** explicit mechanism-family decomposition before producing one unified CWE-level CodeQL query.

Both arms used the same A-level evidence, CodeQL environment, compilation-repair stack, `MAX_REPAIRS=4`, and frozen semantic scoring rubric.

## Main results

At the initial stage, both M0 and M1 compiled on **0/7** TRAIN pairs and had **0/7** strict successes.

The mechanism-first plan itself represented **6/7 actual vulnerability mechanisms**, with one upstream planning miss. However, the initial M1 CodeQL query had **0/7 semantic alignment**, the same as M0.

After one matched V3 compilation repair:

- **M0:** 7/7 compiled, 0/7 strict success.
- **M1:** 7/7 compiled, 1/7 strict success.

Compilation repair therefore successfully restored executability in both arms.

## Final semantic scoring

Using the frozen semantic rubric and actual-mechanism reference:

- **M0 semantic alignment:** 0/7
- **M1 semantic alignment:** 0/7
- **M0 semantic mismatches:** 7/7
- **M1 semantic mismatches:** 7/7
- **M0 generic-template matches:** 7/7
- **M1 generic-template matches:** 7/7
- **Generic-template collapse:** YES for both arms

For M1, **6/7 mechanisms were represented in the plan but all six were lost during unification/CodeQL translation**.

## Important diagnostic case

For **CVE-2023-43668**, M1 achieved the strict hit-based criterion:

`compile ∧ vulnerable_hits >= 1 ∧ patched_hits = 0`

However, semantic scoring still classified the query as:

**WRONG_VULNERABILITY_MECHANISM**

The query detected a generic identifier/key-to-sensitive-operation pattern rather than the actual sensitive JDBC parameter filtering/replacement mechanism.

This demonstrates that **strict hit-based success does not necessarily imply semantic correctness**.

## Interpretation

The pilot does not show that mechanism-first planning improves final semantic alignment.

Instead, it identifies a more specific bottleneck:

> The agent can reason about heterogeneous vulnerability mechanisms at the planning stage, but those mechanism-specific constraints are lost when they are unified into a single CWE-level CodeQL security property.

Compilation support solves a different problem. It makes the query executable, but does not preserve the intended vulnerability semantics.

Therefore, the next intervention should focus on **semantic preservation during mechanism-family unification and CodeQL translation**, rather than adding more mechanism reasoning only before query generation.

## Limitations

This result is limited to one **CWE-639 TRAIN pilot**. TEST was not accessed, and no claim is made about other CWEs or temporal generalization. The result diagnoses the current bottleneck but does not yet demonstrate an intervention that solves semantic preservation.
