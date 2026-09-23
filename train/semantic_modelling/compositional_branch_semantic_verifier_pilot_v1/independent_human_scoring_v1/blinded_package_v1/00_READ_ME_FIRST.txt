T3 BLINDED INDEPENDENT HUMAN SEMANTIC SCORING

Purpose
-------
Independently judge whether the frozen final T3 query preserves the
security semantics of each of the seven frozen TRAIN cases.

Independence requirements
-------------------------
1. The scorer must NOT have seen any prior T3 human score labels,
   rationales, alignment counts, or aggregate semantic results.
2. The scorer must NOT consult ChatGPT, another LLM, or another person
   when selecting labels or writing rationales.
3. The scorer must NOT inspect files outside this blinded package.
4. Do NOT use compilation results, CodeQL hits, vulnerable/patched
   comparisons, prior T0/T1/T2 scores, or cost information.
5. Judge semantic preservation only from:
      - 01_FINAL_T3_QUERY.ql
      - 02_BLINDED_SCORING_PACKET.json

Scoring procedure
-----------------
For each of the seven TRAIN cases:

A. Choose exactly one FINAL QUERY semantic label:

1 = ALIGNED
2 = WRONG_VULNERABILITY_MECHANISM
3 = INCOMPLETE_VULNERABILITY_MECHANISM
4 = MISSING_VALIDATION_SEMANTICS
5 = MISSING_RELATIONAL_CONTEXTUAL_SEMANTICS
6 = INSUFFICIENT_EVIDENCE_UNCLEAR

B. Write one non-empty rationale based only on the frozen query,
   mechanism contract, and frozen TRAIN evidence.

C. Choose exactly one generic-template label:

1 = GENERIC_TEMPLATE_MATCH
2 = NOT_GENERIC_TEMPLATE_MATCH
3 = UNCLEAR

Record all answers in:
03_INDEPENDENT_SCORE_FORM.csv

Important
---------
Do not change the final query or scoring packet.
Do not execute CodeQL.
Do not access TEST data.
Do not compare with any previous scorer.

When all seven rows are complete, return only the completed
03_INDEPENDENT_SCORE_FORM.csv to the experiment owner.
