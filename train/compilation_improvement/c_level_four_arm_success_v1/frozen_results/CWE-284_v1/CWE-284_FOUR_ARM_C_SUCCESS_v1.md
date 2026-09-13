# CWE-284 C-Level Four-Arm Success Result

TRAIN ONLY. TEST forbidden.

| Arm | Final compile | Best compile | Final strict | Best strict | Tokens | Library | Skills |
|---|---:|---:|---:|---:|---:|---:|---:|
| V0_BASELINE_COMPILER_FEEDBACK | 0/14 | 0/14 | 0/14 | 0/14 | 309138 | 0 | 0 |
| V1_LIBRARY_AWARE_REASONING | 0/14 | 0/14 | 0/14 | 0/14 | 986930 | 7 | 0 |
| V2_AUTO_SKILL_RETRIEVAL | 0/14 | 0/14 | 0/14 | 0/14 | 320231 | 0 | 16 |
| V3_LIBRARY_PLUS_AUTO_SKILL | 0/14 | 0/14 | 0/14 | 0/14 | 1082966 | 8 | 16 |

## Main result

All four approaches remained 0/14 compiled and 0/14 strict success through repair4. Unlike CWE-116, neither library-aware reasoning, automatic skills, nor their combination recovered compilation.
