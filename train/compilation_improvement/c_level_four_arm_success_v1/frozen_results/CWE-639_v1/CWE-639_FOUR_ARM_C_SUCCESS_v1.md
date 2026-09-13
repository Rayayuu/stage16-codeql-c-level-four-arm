# CWE-639 C-Level Four-Arm Success Result

TRAIN ONLY. TEST forbidden.

Shared C initial source exploration: 2 events, 1 search, 1 file, 50 lines.

| Arm | Final compile | Best compile | Final strict | Best strict | Tokens | Library | Skills |
|---|---:|---:|---:|---:|---:|---:|---:|
| V0_BASELINE_COMPILER_FEEDBACK | 0/7 | 0/7 | 0/7 | 0/7 | 138536 | 0 | 0 |
| V1_LIBRARY_AWARE_REASONING | 0/7 | 0/7 | 0/7 | 0/7 | 450851 | 8 | 0 |
| V2_AUTO_SKILL_RETRIEVAL | 0/7 | 0/7 | 0/7 | 0/7 | 140073 | 0 | 16 |
| V3_LIBRARY_PLUS_AUTO_SKILL | 0/7 | 0/7 | 0/7 | 0/7 | 296813 | 5 | 16 |

## Main result

All four approaches remained 0/7 compiled and 0/7 strict success through repair4, even though the fresh C-level shared initial had used bounded vulnerable-source exploration.
