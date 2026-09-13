# Four-CWE C-Level Four-Arm Aggregate Result

TRAIN ONLY. TEST forbidden.

CWEs: CWE-116, CWE-284, CWE-434, CWE-639.
Total TRAIN pairs: 39.

## Aggregate arm results

| Arm | Final compile | Best compile | Final strict | Tokens | Library | Skills |
|---|---:|---:|---:|---:|---:|---:|
| V0_BASELINE_COMPILER_FEEDBACK | 0/39 (0.0%) | 0/39 (0.0%) | 0/39 (0.0%) | 760261 | 0 | 0 |
| V1_LIBRARY_AWARE_REASONING | 7/39 (17.95%) | 7/39 (17.95%) | 0/39 (0.0%) | 2333234 | 31 | 0 |
| V2_AUTO_SKILL_RETRIEVAL | 7/39 (17.95%) | 7/39 (17.95%) | 0/39 (0.0%) | 789671 | 0 | 64 |
| V3_LIBRARY_PLUS_AUTO_SKILL | 0/39 (0.0%) | 7/39 (17.95%) | 0/39 (0.0%) | 2196846 | 25 | 60 |

## Main findings

- Strict success remained 0/39 for every arm.
- V1 and V2 recovered compilation only for CWE-116: 7/39 final compiled pairs.
- V3 reached 7/39 best compiled pairs on CWE-116 but regressed to 0/39 final compiled pairs.
- V0 remained 0/39 compiled.
- CWE-284, CWE-434, and CWE-639 were never recovered by any arm.
- Extra assistance increased cost substantially without increasing strict success.

## Interpretation

The primary result is not a universal improvement in success rate. Instead, compilation recovery is strongly CWE-dependent. The same library-aware and skill-based interventions that recover compilation for CWE-116 fail completely on three other CWE classes. Moreover, compilation recovery does not imply vulnerability detection or discrimination success.
