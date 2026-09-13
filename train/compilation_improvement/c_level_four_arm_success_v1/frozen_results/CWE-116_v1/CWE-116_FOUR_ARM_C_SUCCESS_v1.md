# CWE-116 C-Level Four-Arm Success Result

TRAIN ONLY. TEST forbidden.

| Arm | Final compile | Best compile | Final strict | Best strict | Final failure structure | Tokens | Library | Skills |
|---|---:|---:|---:|---:|---|---:|---:|---:|
| V0_BASELINE_COMPILER_FEEDBACK | 0/7 | 0/7 | 0/7 | 0/7 | C=7, D=0, Disc=0 | 126404 | 0 | 0 |
| V1_LIBRARY_AWARE_REASONING | 7/7 | 7/7 | 0/7 | 0/7 | C=0, D=1, Disc=6 | 361253 | 8 | 0 |
| V2_AUTO_SKILL_RETRIEVAL | 7/7 | 7/7 | 0/7 | 0/7 | C=0, D=0, Disc=7 | 133550 | 0 | 16 |
| V3_LIBRARY_PLUS_AUTO_SKILL | 0/7 | 7/7 | 0/7 | 0/7 | C=7, D=0, Disc=0 | 358590 | 6 | 12 |

## Main result

V0 remained 0/7 compiled. V1 and V2 eventually reached 7/7 compilation but remained 0/7 strict success. V3 reached 7/7 compilation at repair3, then regressed to 0/7 compilation at repair4. Therefore compilation assistance helped some arms compile, but did not improve strict success for CWE-116.

No repair arm used bounded C vulnerable-source exploration for this CWE.
