# Semantic-Preservation Translation Pilot — Final Supervisor Summary

## Research question

Given the exact same frozen mechanism-first plan, can an explicit semantic-preservation translation contract reduce plan-to-CodeQL translation loss and generic-template collapse compared with the original M1 translation while retaining compilability?

## Result

For the CWE-639 TRAIN pilot, no semantic improvement was observed.

- T0 original M1 translation: 0/7 semantically aligned, 7/7 generic-template matches, 6/7 plan-to-CodeQL translation losses.
- T1 semantic-preservation translation before CodeQL: 0/7 aligned, 7/7 generic-template matches, 6/7 translation losses.
- After matched V3 repair: semantic labels remained unchanged for all 7/7 cases.
- Compilation improved from 0/7 to 7/7 after two repair iterations.
- Final strict success remained 0/7.
- All seven final cases were detection failures with 0 vulnerable hits.

## Interpretation

The intervention improved neither semantic alignment nor mechanism preservation. The frozen mechanism-first plan represented the actual mechanism for 6/7 cases, but the generated CodeQL still collapsed these heterogeneous mechanisms into a generic external-identifier / Principal-derived-data to sensitive-operation or authorization-decision abstraction.

The matched V3 repair stack successfully corrected CodeQL/API compatibility and restored full compilation, but did not restore the missing ownership, session-identity, certificate-validation, organization-scope, JDBC sensitive-parameter, or SASL protocol semantics.

The observed bottleneck is therefore not compilation alone. In this CWE-639 TRAIN pilot, the dominant failure occurs when mechanism-level security reasoning is unified and translated into one executable CWE-level CodeQL query.

## Scope

TRAIN only. TEST was not accessed. This result should not yet be generalized to other CWEs.
