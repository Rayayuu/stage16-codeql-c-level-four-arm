#!/usr/bin/env python3

from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.util
import json
import time
from pathlib import Path
from typing import Any

from langchain_core.tools import tool
from react_agent.utils import load_chat_model


ROOT = Path(__file__).resolve().parents[3]

PREREG = Path('/home/ray001/codeql_cwe_expansion/stage16_temporal_generalization_gpt5/train/semantic_modelling/structured_mechanism_contract_mapping_pilot_v1/STRUCTURED_MECHANISM_CONTRACT_MAPPING_PREREGISTRATION_v1.json').resolve()
OLD_RUNNER = Path('/home/ray001/codeql_cwe_expansion/stage16_temporal_generalization_gpt5/train/semantic_modelling/mechanism_first_pilot_v1/MECHANISM_FIRST_PILOT_RUNNER_v1.py').resolve()
PLAN = Path('/home/ray001/codeql_cwe_expansion/stage16_temporal_generalization_gpt5/train/semantic_modelling/mechanism_first_pilot_v1/arm_outputs_v1/M1_MECHANISM_FIRST/CWE-639/planning_stage.txt').resolve()
EVIDENCE = Path('/home/ray001/codeql_cwe_expansion/stage16_temporal_generalization_gpt5/train/synthesis_inputs/CWE-639_A_LEVEL_INPUT_v1.json').resolve()

OUT_ROOT = Path('/home/ray001/codeql_cwe_expansion/stage16_temporal_generalization_gpt5/train/semantic_modelling/structured_mechanism_contract_mapping_pilot_v1/t2_generation_v1/CWE-639').resolve()

CONTRACT = (
    OUT_ROOT
    / "structured_contract_mapping.json"
)

QUERY = (
    OUT_ROOT
    / "iter0.ql"
)

METADATA = (
    OUT_ROOT
    / "T2_STRUCTURED_CONTRACT_GENERATION_METADATA.json"
)

EXPECTED_PREREG_SHA = (
    "42e1a2ff920fe40b7db407bb24f6a901ef264c1a401936ee068ac74e0a191fee"
)

EXPECTED_PLAN_SHA = (
    "ea609259a9f8bbed4319249de29915e640fac59cf3631fc664452d092c16368f"
)

EXPECTED_EVIDENCE_SHA = (
    "c2b12964eab7af408e3ae46b2f2bfe1a5c5f8b4aafbc1a3e38b0e510c3a760cf"
)

CWE = "CWE-639"

REQUIRED_CONTRACT_FIELDS = [
    "mechanism_family_id",
    "security_subject_or_principal",
    "protected_target_or_security_object",
    "attacker_controlled_input_or_trigger",
    "decisive_security_relation",
    "required_validation_or_authorization_condition",
    "security_sensitive_effect",
]

REQUIRED_MAPPING_FIELDS = [
    "mechanism_family_id",
    "source_predicate_or_condition",
    "target_predicate_or_condition",
    "relation_or_validation_predicate",
    "query_branch_or_join_condition",
    "encoded_status",
    "bounded_limitation_if_not_encoded",
]


def H(path: Path) -> str:
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest()


def load_old_pilot():
    spec = importlib.util.spec_from_file_location(
        "_structured_contract_old_pilot",
        OLD_RUNNER,
    )

    if spec is None or spec.loader is None:
        raise RuntimeError(
            "OLD_RUNNER_IMPORT_FAILED"
        )

    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_original():
    return load_old_pilot().load_original()


def treatment_instruction() -> str:
    return """
===== T2 STRUCTURED MECHANISM-CONTRACT -> CODEQL TRANSLATION =====

You are translating an already-frozen mechanism-first security plan into
ONE CWE-level Java CodeQL query.

Before writing CodeQL, explicitly represent every distinct mechanism family
that is present in the frozen plan as a structured contract containing:

1. mechanism_family_id
2. security_subject_or_principal
3. protected_target_or_security_object
4. attacker_controlled_input_or_trigger
5. decisive_security_relation
6. required_validation_or_authorization_condition
7. security_sensitive_effect

For every contract, also provide a CodeQL mapping containing:

1. mechanism_family_id
2. source_predicate_or_condition
3. target_predicate_or_condition
4. relation_or_validation_predicate
5. query_branch_or_join_condition
6. encoded_status
7. bounded_limitation_if_not_encoded

CRITICAL SEMANTIC-PRESERVATION RULES

- Every mechanism family represented in the frozen plan must receive its own
  explicit contract and CodeQL mapping.
- Do not silently replace heterogeneous mechanisms with a generic
  user-controlled ID/key -> sensitive-operation taint pattern.
- A generic identifier flow does NOT by itself encode ownership,
  authenticated-session identity, certificate validation,
  organization/tenant scope, sensitive configuration filtering,
  protocol-authentication conditions, or other decisive relations.
- Each decisive relation or validation condition must be visible in an
  explicit predicate, join condition, or dedicated query branch.
- Multi-branch structure inside the ONE CWE-level query is allowed and
  preferred when mechanism families are heterogeneous.
- If a mechanism from the frozen plan cannot be faithfully represented using
  the available CodeQL model, mark encoded_status as
  UNENCODABLE_OR_BOUNDED and explain the limitation. Do NOT replace it with
  a generic surrogate just to make the query look complete.
- Do not invent mechanisms absent from the frozen plan.
- Do not hard-code CVE IDs, repository names, filenames, paths, commit hashes,
  exploit strings, or case-specific constants in the CodeQL.
- Do not create per-CVE queries.
- Do not inspect repository source, patch/source B/C evidence, prior target
  queries, semantic scoring results, hit results, repair trajectories, network
  sources, or TEST.

OUTPUT REQUIREMENT

You have exactly ONE generation model call.
You must call write_structured_contract_and_query exactly once.
That single tool call must provide:
(a) structured_contract_mapping_json
(b) query_text

Do not evaluate, compile, or repair the query.
"""


def build_prompt() -> str:
    plan = PLAN.read_text(
        encoding="utf-8",
        errors="replace",
    )

    evidence = EVIDENCE.read_text(
        encoding="utf-8",
        errors="replace",
    )

    return (
        "===== A-LEVEL TRAIN EVIDENCE =====\n"
        + evidence
        + "\n===== END A-LEVEL TRAIN EVIDENCE =====\n\n"
        + "===== EXACT FROZEN MECHANISM-FIRST PLAN =====\n"
        + plan
        + "\n===== END EXACT FROZEN MECHANISM-FIRST PLAN =====\n\n"
        + treatment_instruction()
    )


def validate_contract_payload(
    payload: dict[str, Any],
) -> None:
    contracts = payload.get(
        "mechanism_contracts"
    )

    mappings = payload.get(
        "codeql_mappings"
    )

    if not isinstance(contracts, list) or not contracts:
        raise RuntimeError(
            "INVALID_OR_EMPTY_MECHANISM_CONTRACTS"
        )

    if not isinstance(mappings, list) or not mappings:
        raise RuntimeError(
            "INVALID_OR_EMPTY_CODEQL_MAPPINGS"
        )

    contract_ids = []

    for i, item in enumerate(contracts):
        if not isinstance(item, dict):
            raise RuntimeError(
                f"CONTRACT_{i}_NOT_OBJECT"
            )

        missing = [
            k
            for k in REQUIRED_CONTRACT_FIELDS
            if k not in item
        ]

        if missing:
            raise RuntimeError(
                "CONTRACT_MISSING_FIELDS="
                + json.dumps(missing)
            )

        cid = str(
            item["mechanism_family_id"]
        ).strip()

        if not cid:
            raise RuntimeError(
                "EMPTY_MECHANISM_FAMILY_ID"
            )

        contract_ids.append(cid)

    if len(contract_ids) != len(set(contract_ids)):
        raise RuntimeError(
            "DUPLICATE_MECHANISM_FAMILY_IDS"
        )

    mapping_ids = []

    allowed_status = {
        "ENCODED",
        "PARTIALLY_ENCODED",
        "UNENCODABLE_OR_BOUNDED",
    }

    for i, item in enumerate(mappings):
        if not isinstance(item, dict):
            raise RuntimeError(
                f"MAPPING_{i}_NOT_OBJECT"
            )

        missing = [
            k
            for k in REQUIRED_MAPPING_FIELDS
            if k not in item
        ]

        if missing:
            raise RuntimeError(
                "MAPPING_MISSING_FIELDS="
                + json.dumps(missing)
            )

        mid = str(
            item["mechanism_family_id"]
        ).strip()

        mapping_ids.append(mid)

        status = str(
            item["encoded_status"]
        ).strip()

        if status not in allowed_status:
            raise RuntimeError(
                "INVALID_ENCODED_STATUS="
                + status
            )

        if (
            status
            == "UNENCODABLE_OR_BOUNDED"
            and not str(
                item[
                    "bounded_limitation_if_not_encoded"
                ]
            ).strip()
        ):
            raise RuntimeError(
                "UNENCODABLE_WITHOUT_LIMITATION"
            )

    if len(mapping_ids) != len(set(mapping_ids)):
        raise RuntimeError(
            "DUPLICATE_MAPPING_FAMILY_IDS"
        )

    if set(contract_ids) != set(mapping_ids):
        raise RuntimeError(
            "CONTRACT_MAPPING_ID_SET_MISMATCH"
        )


async def generate() -> None:
    if OUT_ROOT.exists():
        raise RuntimeError(
            "T2_GENERATION_OUTPUT_ALREADY_EXISTS="
            + str(OUT_ROOT)
        )

    if H(PREREG) != EXPECTED_PREREG_SHA:
        raise RuntimeError(
            "PREREG_SHA_MISMATCH"
        )

    if H(PLAN) != EXPECTED_PLAN_SHA:
        raise RuntimeError(
            "FROZEN_PLAN_SHA_MISMATCH"
        )

    if H(EVIDENCE) != EXPECTED_EVIDENCE_SHA:
        raise RuntimeError(
            "EVIDENCE_SHA_MISMATCH"
        )

    orig = load_original()

    tool_state = {
        "written": False,
        "result": None,
    }

    @tool
    def write_structured_contract_and_query(
        structured_contract_mapping_json: str,
        query_text: str,
    ) -> dict[str, Any]:
        """
        Write the structured mechanism-contract/CodeQL mapping and exactly one
        CWE-level Java CodeQL query.
        """

        if tool_state["written"]:
            return {
                "ok": False,
                "error":
                    "STRUCTURED_OUTPUT_ALREADY_WRITTEN",
            }

        try:
            payload = json.loads(
                structured_contract_mapping_json
            )
        except Exception as exc:
            return {
                "ok": False,
                "error":
                    "INVALID_CONTRACT_JSON="
                    + repr(exc),
            }

        try:
            validate_contract_payload(
                payload
            )
        except Exception as exc:
            return {
                "ok": False,
                "error":
                    "CONTRACT_VALIDATION_FAILED="
                    + str(exc),
            }

        q = query_text.strip()

        if q.startswith("```"):
            lines = q.splitlines()

            if lines and lines[0].startswith("```"):
                lines = lines[1:]

            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]

            q = "\n".join(lines).strip()

        if not q:
            return {
                "ok": False,
                "error":
                    "EMPTY_QUERY",
            }

        OUT_ROOT.mkdir(
            parents=True,
            exist_ok=False,
        )

        CONTRACT.write_text(
            json.dumps(
                payload,
                indent=2,
                ensure_ascii=False,
            )
            + "\n",
            encoding="utf-8",
        )

        QUERY.write_text(
            q + "\n",
            encoding="utf-8",
        )

        result = {
            "ok": True,
            "contract_path":
                str(CONTRACT),
            "contract_sha256":
                H(CONTRACT),
            "query_path":
                str(QUERY),
            "query_sha256":
                H(QUERY),
            "mechanism_contract_count":
                len(
                    payload[
                        "mechanism_contracts"
                    ]
                ),
            "codeql_mapping_count":
                len(
                    payload[
                        "codeql_mappings"
                    ]
                ),
        }

        tool_state["written"] = True
        tool_state["result"] = result

        return result

    model = (
        load_chat_model(
            orig.MODEL
        )
        .bind_tools(
            [write_structured_contract_and_query]
        )
    )

    prompt = build_prompt()

    wall_start = time.perf_counter()

    response = await model.ainvoke([
        {
            "role": "system",
            "content":
                orig.base.SYSTEM_PROMPT,
        },
        {
            "role": "user",
            "content": prompt,
        },
    ])

    wall_sec = round(
        time.perf_counter()
        - wall_start,
        6,
    )

    calls = response.tool_calls or []

    if len(calls) != 1:
        raise RuntimeError(
            "EXPECTED_EXACTLY_ONE_TOOL_CALL_GOT="
            + str(len(calls))
        )

    call = calls[0]

    if (
        call.get("name")
        != "write_structured_contract_and_query"
    ):
        raise RuntimeError(
            "UNEXPECTED_TOOL_CALL="
            + str(call.get("name"))
        )

    result = (
        write_structured_contract_and_query
        .invoke(
            call.get("args", {})
        )
    )

    if not result.get("ok"):
        raise RuntimeError(
            "STRUCTURED_WRITE_FAILED="
            + json.dumps(
                result,
                ensure_ascii=False,
            )
        )

    usage = orig.parse_model_usage(
        response
    )

    metadata = {
        "schema_version":
            "1.0",
        "scope":
            "TRAIN_ONLY",
        "stage":
            "T2_STRUCTURED_CONTRACT_MAPPING_GENERATION",
        "model":
            orig.MODEL,
        "model_call_count":
            1,
        "token_usage":
            usage,
        "wall_clock_sec":
            wall_sec,
        "frozen_plan_path":
            str(PLAN),
        "frozen_plan_sha256":
            H(PLAN),
        "A_level_evidence_path":
            str(EVIDENCE),
        "A_level_evidence_sha256":
            H(EVIDENCE),
        "contract_path":
            str(CONTRACT),
        "contract_sha256":
            H(CONTRACT),
        "query_path":
            str(QUERY),
        "query_sha256":
            H(QUERY),
        "mechanism_contract_count":
            result[
                "mechanism_contract_count"
            ],
        "codeql_mapping_count":
            result[
                "codeql_mapping_count"
            ],
        "human_semantic_reference_visible":
            False,
        "prior_T0_T1_semantic_scores_visible":
            False,
        "prior_hit_results_visible":
            False,
        "prior_repair_trajectory_visible":
            False,
        "patch_or_bounded_source_evidence_visible":
            False,
        "repository_source_visible":
            False,
        "manual_query_modification":
            False,
        "codeql_execution":
            False,
        "test_access":
            "FORBIDDEN",
    }

    METADATA.write_text(
        json.dumps(
            metadata,
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    print(
        json.dumps(
            metadata,
            indent=2,
            ensure_ascii=False,
        )
    )


def self_check() -> dict[str, Any]:
    checks = {}

    for name, p in [
        ("prereg", PREREG),
        ("old_runner", OLD_RUNNER),
        ("plan", PLAN),
        ("evidence", EVIDENCE),
    ]:
        checks[
            name + "_exists"
        ] = p.is_file()

    checks["prereg_sha_frozen"] = (
        PREREG.is_file()
        and H(PREREG)
        == EXPECTED_PREREG_SHA
    )

    checks["plan_sha_frozen"] = (
        PLAN.is_file()
        and H(PLAN)
        == EXPECTED_PLAN_SHA
    )

    checks["evidence_sha_frozen"] = (
        EVIDENCE.is_file()
        and H(EVIDENCE)
        == EXPECTED_EVIDENCE_SHA
    )

    try:
        orig = load_original()
        checks["old_runner_import"] = True
        checks["model_present"] = bool(
            orig.MODEL
        )
        checks["system_prompt_present"] = bool(
            orig.base.SYSTEM_PROMPT
        )
        checks["parse_model_usage_present"] = hasattr(
            orig,
            "parse_model_usage",
        )
    except Exception:
        checks["old_runner_import"] = False
        checks["model_present"] = False
        checks["system_prompt_present"] = False
        checks["parse_model_usage_present"] = False

    checks["output_root_absent"] = (
        not OUT_ROOT.exists()
    )

    checks["contract_absent"] = (
        not CONTRACT.exists()
    )

    checks["query_absent"] = (
        not QUERY.exists()
    )

    checks["metadata_absent"] = (
        not METADATA.exists()
    )

    instruction = treatment_instruction()

    checks["requires_contract_fields"] = all(
        x in instruction
        for x in REQUIRED_CONTRACT_FIELDS
    )

    checks["requires_mapping_fields"] = all(
        x in instruction
        for x in REQUIRED_MAPPING_FIELDS
    )

    checks["forbids_generic_silent_collapse"] = (
        "Do not silently replace heterogeneous mechanisms"
        in instruction
    )

    checks["requires_unencodable_marker"] = (
        "UNENCODABLE_OR_BOUNDED"
        in instruction
    )

    checks["one_cwe_query_required"] = (
        "ONE CWE-level Java CodeQL query"
        in instruction
    )

    checks["one_generation_call_required"] = (
        "exactly ONE generation model call"
        in instruction
    )

    checks["no_test_instruction"] = (
        "TEST"
        in instruction
        and "Do not inspect"
        in instruction
    )

    # Generation prompt is constructed only from the two preregistered
    # allowed frozen inputs plus the T2 treatment instruction.
    checks["prompt_inputs_only_plan_evidence_treatment"] = True

    # These prior-result artifacts are intentionally not referenced anywhere
    # by the generation harness.
    source = Path(__file__).read_text(
        encoding="utf-8",
        errors="replace",
    )

    prohibited_artifact_tokens = [
        "FINAL_SEMANTIC_PRESERVATION_TRANSLATION_SYNTHESIS",
        "T1_POST_REPAIR_SEMANTIC_SCORES",
        "T1_MATCHED_V3_REPAIR_OUTCOME",
        "FINAL_REPAIRED_QUERY_SEMANTIC_SCORES",
        "SUPERVISOR_TAXONOMY",
    ]

    checks["no_prior_result_artifact_reference"] = not any(
        token in source
        for token in prohibited_artifact_tokens
    )

    return {
        "status":
            "PASS"
            if all(checks.values())
            else "FAIL",
        "checks":
            checks,
        "model_call_budget":
            1,
        "generation_inputs": [
            str(EVIDENCE),
            str(PLAN),
            "T2 treatment instruction",
        ],
        "generation_outputs": [
            str(CONTRACT),
            str(QUERY),
            str(METADATA),
        ],
        "model_execution":
            False,
        "codeql_execution":
            False,
        "test_access":
            "FORBIDDEN",
    }


def main():
    p = argparse.ArgumentParser()

    p.add_argument(
        "--self-check",
        action="store_true",
    )

    p.add_argument(
        "--generate",
        action="store_true",
    )

    args = p.parse_args()

    if args.self_check:
        result = self_check()

        print(
            json.dumps(
                result,
                indent=2,
                ensure_ascii=False,
            )
        )

        raise SystemExit(
            0
            if result["status"] == "PASS"
            else 2
        )

    if args.generate:
        asyncio.run(
            generate()
        )
        return

    raise SystemExit(
        "Specify --self-check or --generate"
    )


if __name__ == "__main__":
    main()
