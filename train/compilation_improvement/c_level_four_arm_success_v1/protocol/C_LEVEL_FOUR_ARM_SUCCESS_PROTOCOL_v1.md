# Stage16 C-Level Four-Arm Success Experiment Protocol v1

## Scope

TRAIN ONLY.

TEST access is forbidden.

No TEST source, advisory, diff, database, result, or metadata may be inspected before the later explicit scientific freeze and supervisor approval.

Target CWEs:

- CWE-116: 7 TRAIN pairs
- CWE-284: 14 TRAIN pairs
- CWE-434: 11 TRAIN pairs
- CWE-639: 7 TRAIN pairs

Total: 39 frozen TRAIN vulnerable-patched pairs.

## Research Question

Now that compilation assistance can substantially restore CodeQL compilation, determine whether four assistance strategies improve strict vulnerability-detection success under evidence level C, where the agent is allowed bounded vulnerable-source exploration.

The four arms are:

- V0_BASELINE_COMPILER_FEEDBACK
- V1_LIBRARY_AWARE_REASONING
- V2_AUTO_SKILL_RETRIEVAL
- V3_LIBRARY_PLUS_AUTO_SKILL

Arm semantics must remain identical to the previously validated clean four-arm implementation except for integration with the frozen C-level synthesis/evaluation loop.

## Frozen Evidence Level C

Evidence C consists of:

A. historical pre-cutoff advisory evidence;
B. frozen Java patch diff;
C. bounded vulnerable-source exploration.

C exploration is restricted to frozen TRAIN vulnerable source only.

Patched source browsing is forbidden beyond the supplied frozen B patch evidence.

No network lookup is allowed.

Search anchors must occur literally in frozen A/B evidence.

Per TRAIN benchmark:

- maximum anchor searches: 5
- maximum distinct Java files opened: 10
- maximum vulnerable-source lines exposed: 500
- maximum lines per read: 50
- exploration depth: one hop

A Java file may only be read if it was directly returned by an allowed anchor search.

Newly discovered source text may not be used as a new repository-wide search anchor.

## Shared C-Level Initial

For each CWE, exactly ONE fresh C-level initial query is generated.

The initial synthesis has access to the frozen A/B evidence and the original bounded C vulnerable-source tools.

No arm-specific library or skill intervention is visible during shared-initial generation.

The exact initial query bytes are frozen and forked identically into all four arms.

The shared-initial query SHA256 must be identical across all four arms.

### C Exploration State Fairness

The shared-initial stage may consume part of the frozen C exploration budget.

Therefore each arm MUST inherit an identical clone of the complete post-initial C exploration state, including:

- searches used per benchmark;
- searched anchors;
- directly returned Java-file sets for each searched anchor;
- distinct files already opened;
- source lines already exposed;
- source snippets/tool observations already exposed during the shared initial.

The four arms must receive the same remaining C exploration budget.

No arm may reset or receive a second full C exploration budget after the shared initial.

This preserves the original C-level evidence budget and prevents evidence-budget confounding.

## Common TRAIN Feedback

After every query attempt, all arms receive the same frozen TRAIN evaluator outputs needed for repair:

- compilation status;
- vulnerable_hits;
- patched_hits;
- pair_success;
- compiler error feedback when compilation fails.

These pair-level evaluator results are common C-experiment feedback and are not considered an arm-specific intervention.

No TEST feedback is available.

## Strict Success

A TRAIN pair succeeds iff:

compile AND vulnerable_hits >= 1 AND patched_hits == 0

Primary pair-level success rate:

successful TRAIN pairs / total TRAIN pairs.

CWE-level complete success requires every frozen TRAIN pair for that CWE to satisfy strict success using the same CWE-level query.

## Repair and Stop Rule

Maximum repairs: 4.

Attempts are:

- C_initial
- repair1
- repair2
- repair3
- repair4

Compilation alone is NOT a stopping condition.

An arm stops only when:

1. all frozen TRAIN pairs for the CWE satisfy strict success; or
2. repair4 has been evaluated.

Therefore a fully compiling query with detection or discrimination failures must remain eligible for repair.

The terminal query is the final evaluated attempt unless all-pair strict success was achieved earlier.

For analysis, both final and best successful_pair_count across attempts must be recorded so repair regression is visible rather than hidden.

No additional repair beyond repair4 is permitted.

## Arm-Specific Intervention

V0_BASELINE_COMPILER_FEEDBACK:
- common C evidence and TRAIN evaluation feedback only;
- no CodeQL library lookup;
- no automatically retrieved compilation skill.

V1_LIBRARY_AWARE_REASONING:
- same common evidence and feedback;
- at most 2 read-only CodeQL java-all library lookups per repair;
- no automatically retrieved compilation skill.

V2_AUTO_SKILL_RETRIEVAL:
- same common evidence and feedback;
- automatically retrieve at most 4 reusable compilation skills per repair;
- no live CodeQL library lookup.

V3_LIBRARY_PLUS_AUTO_SKILL:
- same common evidence and feedback;
- at most 2 read-only CodeQL java-all library lookups per repair;
- automatically retrieve at most 4 reusable compilation skills per repair.

Maximum model turns per repair remains 6.

Library/skill assistance must not introduce TEST evidence, repository-specific target trajectories, CVE-specific constants, commit hashes, filenames, exact repository paths, or exploit-specific constants.

## Experimental Controls

The following are held fixed across arms:

- target CWE and TRAIN pairs;
- shared C-level initial query;
- post-initial C exploration state and remaining source budget;
- model;
- CodeQL version;
- java-all library version;
- declared QL pack;
- evaluator;
- success definition;
- repair budget;
- C source exploration policy;
- no per-CVE tuning.

No generated query may be manually edited.

## Output Isolation

This experiment must use a new result namespace under:

train/compilation_improvement/c_level_four_arm_success_v1/

It must not read cached scientific results from the old:

train/query_evaluations/<CWE>/C_initial or C_repair*

directories.

It must not overwrite:

- original A/B/C Stage16 results;
- frozen TRAIN outcomes;
- corrected replacement v2 four-arm compilation results;
- supervisor summaries.

Every new query and evaluation artifact must live inside the new declared C-success QL pack/result namespace.

Existing-output collision must cause a hard failure rather than reuse or overwrite.

## Metrics

For every CWE, arm, and attempt record:

- train_case_count;
- compiled_pair_count;
- successful_pair_count;
- pair-level vulnerable_hits;
- pair-level patched_hits;
- pair_success;
- compilation failures;
- detection failures: compiled AND vulnerable_hits == 0;
- discrimination failures: compiled AND vulnerable_hits >= 1 AND patched_hits > 0;
- repair count;
- final and best compilation counts;
- final and best strict-success counts;
- terminal reason;
- token usage;
- model wall-clock time;
- CodeQL runtime;
- library lookup count;
- retrieved skill count;
- C source search/file/line usage.

Shared-initial generation cost must be reported separately from arm-incremental repair cost.

## Scientific Restrictions

TRAIN ONLY.

TEST forbidden.

No database rebuilding.

No rerunning frozen original scientific outcomes.

No manual query editing.

No per-CVE tuning.

No arm-specific initial synthesis.

No expansion of C source-exploration budget.

No expansion of MAX_REPAIRS=4.

