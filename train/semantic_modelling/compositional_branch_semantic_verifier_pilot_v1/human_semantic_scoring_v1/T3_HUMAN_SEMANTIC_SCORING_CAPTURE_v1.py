#!/usr/bin/env python3

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path


ROOT = Path(
    "/home/ray001/codeql_cwe_expansion/stage16_temporal_generalization_gpt5/"
    "train/semantic_modelling/compositional_branch_semantic_verifier_pilot_v1"
)

PACKET = (
    ROOT
    / "human_semantic_scoring_v1"
    / "T3_HUMAN_SEMANTIC_SCORING_PACKET_v1.json"
)

DRAFT_CSV = (
    ROOT
    / "human_semantic_scoring_v1"
    / "T3_HUMAN_SEMANTIC_SCORES_DRAFT_v1.csv"
)

DRAFT_JSON = (
    ROOT
    / "human_semantic_scoring_v1"
    / "T3_HUMAN_SEMANTIC_SCORES_DRAFT_v1.json"
)

EXPECTED_PACKET_SHA = (
    "fcaf785ca09e6d466f2646fa194f4399"
    "b10c55f734a26dbcfcde1a02ceecdec5"
)


def H(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def contains_case(value, case_id: str) -> bool:
    try:
        text = json.dumps(
            value,
            ensure_ascii=False,
        )
    except Exception:
        text = str(value)

    return case_id.lower() in text.lower()


def find_case_contexts(value, case_id: str, out):
    if isinstance(value, dict):
        if contains_case(value, case_id):
            direct = any(
                case_id.lower() in str(v).lower()
                for v in value.values()
                if not isinstance(v, (dict, list))
            )

            if direct:
                out.append(value)

        for v in value.values():
            find_case_contexts(
                v,
                case_id,
                out,
            )

    elif isinstance(value, list):
        for v in value:
            find_case_contexts(
                v,
                case_id,
                out,
            )


def choose(prompt: str, options):
    while True:
        print()
        for i, option in enumerate(
            options,
            start=1,
        ):
            print(f"  {i}. {option}")

        raw = input(
            prompt
        ).strip()

        if raw.isdigit():
            idx = int(raw)

            if 1 <= idx <= len(options):
                return options[idx - 1]

        print(
            "INVALID_SELECTION: please enter one listed number."
        )


if H(PACKET) != EXPECTED_PACKET_SHA:
    raise SystemExit(
        "ABORT_PACKET_SHA_MISMATCH"
    )

if DRAFT_CSV.exists() or DRAFT_JSON.exists():
    raise SystemExit(
        "ABORT_DRAFT_ALREADY_EXISTS_REFUSING_OVERWRITE"
    )

packet = json.loads(
    PACKET.read_text(
        encoding="utf-8"
    )
)

if (
    packet.get("test_access")
    != "FORBIDDEN"
):
    raise SystemExit(
        "ABORT_TEST_STATE_INVALID"
    )

if (
    packet.get(
        "human_semantic_scoring_completed"
    )
    is not False
):
    raise SystemExit(
        "ABORT_PACKET_NOT_BLANK"
    )

anti = packet.get(
    "anti_leakage",
    {}
)

if any(
    [
        anti.get(
            "prior_T0_T1_T2_semantic_score_values_visible"
        ),
        anti.get(
            "compiler_outcome_visible"
        ),
        anti.get(
            "codeql_hit_results_visible"
        ),
        anti.get(
            "patched_vulnerable_comparison_visible"
        ),
        anti.get(
            "test_information_visible"
        ),
    ]
):
    raise SystemExit(
        "ABORT_ANTI_LEAKAGE_STATE_INVALID"
    )

semantic_labels = packet[
    "allowed_final_query_semantic_labels"
]

generic_labels = packet[
    "allowed_generic_template_labels"
]

forms = packet[
    "case_scoring_form"
]

reference = packet[
    "frozen_reference_material"
]

contracts = {
    x["mechanism_family_id"]:
        x
    for x in reference[
        "t2_mechanism_contracts_only"
    ]
}

evidence = reference[
    "a_level_train_evidence"
]

query_text = reference[
    "final_t3_query_text"
]

print()
print(
    "============================================================"
)
print(
    "FROZEN T3 FINAL QUERY — READ BEFORE SCORING"
)
print(
    "============================================================"
)
print(query_text)
print(
    "============================================================"
)

print()
print(
    "SCORING RULE:"
)
print(
    "Judge semantic preservation only. Do NOT consider compilation,"
)
print(
    "hits, vulnerable/patched outcomes, cost, or prior T0/T1/T2 scores."
)
print(
    "A query is not ALIGNED merely because it contains generic ID/resource"
)
print(
    "vocabulary; the decisive case-specific security semantics matter."
)

results = []

for index, row in enumerate(
    forms,
    start=1,
):
    case_id = row[
        "case_id"
    ]

    family = row[
        "mechanism_family_id"
    ]

    contract = contracts[
        family
    ]

    print()
    print(
        "############################################################"
    )
    print(
        f"CASE {index}/7: {case_id}"
    )
    print(
        f"MECHANISM FAMILY: {family}"
    )
    print(
        "############################################################"
    )

    print()
    print(
        "FROZEN MECHANISM CONTRACT:"
    )
    print(
        json.dumps(
            contract,
            indent=2,
            ensure_ascii=False,
        )
    )

    contexts = []
    find_case_contexts(
        evidence,
        case_id,
        contexts,
    )

    print()
    print(
        "FROZEN TRAIN EVIDENCE FOR THIS CASE:"
    )

    if contexts:
        unique = []
        seen = set()

        for obj in contexts:
            raw = json.dumps(
                obj,
                ensure_ascii=False,
                sort_keys=True,
            )

            digest = hashlib.sha256(
                raw.encode("utf-8")
            ).hexdigest()

            if digest not in seen:
                seen.add(digest)
                unique.append(obj)

        for j, obj in enumerate(
            unique[:3],
            start=1,
        ):
            print(
                f"--- evidence context {j} ---"
            )
            print(
                json.dumps(
                    obj,
                    indent=2,
                    ensure_ascii=False,
                )[:8000]
            )

    else:
        print(
            "No direct CVE-keyed object found in evidence snapshot."
        )

    semantic = choose(
        "\nSelect FINAL QUERY semantic label [1-6]: ",
        semantic_labels,
    )

    print()
    print(
        f"SELECTED_SEMANTIC_LABEL={semantic}"
    )

    while True:
        rationale = input(
            "Enter your human rationale (non-empty, one line): "
        ).strip()

        if rationale:
            break

        print(
            "RATIONALE_MUST_NOT_BE_EMPTY"
        )

    generic = choose(
        "\nSelect generic-template label [1-3]: ",
        generic_labels,
    )

    print(
        f"SELECTED_GENERIC_TEMPLATE_LABEL={generic}"
    )

    results.append(
        {
            "case_id":
                case_id,

            "mechanism_family_id":
                family,

            "final_query_semantic_label":
                semantic,

            "rationale":
                rationale,

            "generic_template_label":
                generic,

            "human_score_completed":
                "YES",
        }
    )


with DRAFT_CSV.open(
    "w",
    encoding="utf-8",
    newline="",
) as f:
    writer = csv.DictWriter(
        f,
        fieldnames=[
            "case_id",
            "mechanism_family_id",
            "final_query_semantic_label",
            "rationale",
            "generic_template_label",
            "human_score_completed",
        ],
        lineterminator="\n",
    )

    writer.writeheader()
    writer.writerows(
        results
    )


aligned_count = sum(
    r[
        "final_query_semantic_label"
    ]
    == "ALIGNED"
    for r in results
)

mismatch_count = (
    len(results)
    - aligned_count
)

generic_count = sum(
    r[
        "generic_template_label"
    ]
    == "GENERIC_TEMPLATE_MATCH"
    for r in results
)

generic_binary = (
    "YES"
    if generic_count >= 4
    else "NO"
)

draft = {
    "schema_version":
        "1.0",

    "stage":
        "T3_PRE_CODEQL_INDEPENDENT_HUMAN_SEMANTIC_SCORING_DRAFT",

    "scope":
        "CWE-639 TRAIN ONLY",

    "scorer_type":
        "HUMAN",

    "source_packet_sha256":
        H(PACKET),

    "train_case_count":
        7,

    "case_scores":
        results,

    "semantic_alignment_count":
        aligned_count,

    "semantic_mismatch_count":
        mismatch_count,

    "generic_template_match_count":
        generic_count,

    "generic_template_collapse":
        generic_binary,

    "compiler_outcome_visible":
        False,

    "codeql_hit_results_visible":
        False,

    "patched_vulnerable_comparison_visible":
        False,

    "prior_T0_T1_T2_score_values_visible":
        False,

    "model_execution":
        False,

    "codeql_execution":
        False,

    "query_modification":
        False,

    "test_access":
        "FORBIDDEN",

    "status":
        "HUMAN_SCORING_CAPTURED_NOT_YET_FROZEN",
}

DRAFT_JSON.write_text(
    json.dumps(
        draft,
        indent=2,
        ensure_ascii=False,
    )
    + "\n",
    encoding="utf-8",
)

print()
print(
    "============================================================"
)
print(
    "HUMAN SCORING CAPTURE COMPLETE — NOT YET FROZEN"
)
print(
    "============================================================"
)

for r in results:
    print(
        r["case_id"]
        + " | "
        + r["final_query_semantic_label"]
        + " | "
        + r["generic_template_label"]
    )

print()
print(
    f"SEMANTIC_ALIGNMENT_COUNT={aligned_count}/7"
)
print(
    f"SEMANTIC_MISMATCH_COUNT={mismatch_count}/7"
)
print(
    f"GENERIC_TEMPLATE_MATCH_COUNT={generic_count}/7"
)
print(
    f"GENERIC_TEMPLATE_COLLAPSE={generic_binary}"
)

print(
    f"DRAFT_CSV_SHA256={H(DRAFT_CSV)}"
)
print(
    f"DRAFT_JSON_SHA256={H(DRAFT_JSON)}"
)

print(
    "HUMAN_SCORING_CAPTURED=YES"
)
print(
    "HUMAN_SCORING_FORMALLY_FROZEN=NO"
)
print(
    "CODEQL_EXECUTION_ALLOWED_NOW=NO"
)
print(
    "TEST_ACCESSED=NO"
)
print(
    "NEXT_STAGE=READ_ONLY_AUDIT_AND_FREEZE_INDEPENDENT_HUMAN_SEMANTIC_SCORES"
)
