#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.util
import json
import re
import time
from pathlib import Path

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.tools import tool

ROOT = Path('/home/ray001/codeql_cwe_expansion/stage16_temporal_generalization_gpt5')
PILOT_ROOT = Path('/home/ray001/codeql_cwe_expansion/stage16_temporal_generalization_gpt5/train/semantic_modelling/compositional_branch_semantic_verifier_pilot_v1')
INPUT_ROOT = Path('/home/ray001/codeql_cwe_expansion/stage16_temporal_generalization_gpt5/train/semantic_modelling/compositional_branch_semantic_verifier_pilot_v1/branch_inputs_v1')
OUTPUT_ROOT = Path('/home/ray001/codeql_cwe_expansion/stage16_temporal_generalization_gpt5/train/semantic_modelling/compositional_branch_semantic_verifier_pilot_v1/branch_generation_v1')
T2_RUNNER = Path('/home/ray001/codeql_cwe_expansion/stage16_temporal_generalization_gpt5/train/semantic_modelling/structured_mechanism_contract_mapping_pilot_v1/STRUCTURED_MECHANISM_CONTRACT_MAPPING_RUNNER_v1_1.py')

FAMILIES = {'idor_user_controlled_identifier_to_resource_operation': {'section': 1, 'module': 'T3BranchIdor', 'cves': ['CVE-2020-23449', 'CVE-2023-2260', 'CVE-2023-30216', 'CVE-2023-32310']}, 'bypass_via_missing_or_optional_identity_component': {'section': 2, 'module': 'T3BranchOptionalIdentity', 'cves': ['CVE-2023-43668', 'CVE-2023-44981']}, 'improper_authentication_certificate_reuse': {'section': 3, 'module': 'T3BranchCertificateReuse', 'cves': ['CVE-2021-4142']}}

MODEL_CALL_BUDGET_PER_BRANCH = 1


def H(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def load_t2_runner():
    spec = importlib.util.spec_from_file_location(
        "_t3_frozen_t2_runner",
        T2_RUNNER,
    )

    if spec is None or spec.loader is None:
        raise RuntimeError("T2_RUNNER_IMPORT_FAILURE")

    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def resolve_original(t2):
    if not hasattr(t2, "load_original"):
        raise RuntimeError(
            "T2_RUNNER_MISSING_load_original"
        )

    return t2.load_original()


def resolve_model_loader(t2, original):
    for obj in [t2, original]:
        fn = getattr(
            obj,
            "load_chat_model",
            None,
        )

        if callable(fn):
            return fn

    raise RuntimeError(
        "NO_COMPATIBLE_load_chat_model"
    )


def get_model_name(t2, original):
    for obj in [original, t2]:
        value = getattr(
            obj,
            "MODEL",
            None,
        )

        if isinstance(value, str) and value:
            return value

    raise RuntimeError(
        "MODEL_NAME_NOT_FOUND"
    )


def get_system_prompt(original):
    value = getattr(
        original,
        "SYSTEM_PROMPT",
        None,
    )

    if not isinstance(value, str) or not value.strip():
        raise RuntimeError(
            "SYSTEM_PROMPT_NOT_FOUND"
        )

    return value


def normalized_usage(response):
    raw = getattr(
        response,
        "usage_metadata",
        None,
    )

    if raw is None:
        raw = {}

    result = {
        "input_tokens":
            raw.get("input_tokens"),

        "output_tokens":
            raw.get("output_tokens"),

        "total_tokens":
            raw.get("total_tokens"),

        "raw_usage_metadata":
            raw,
    }

    response_metadata = getattr(
        response,
        "response_metadata",
        None,
    )

    if response_metadata:
        result[
            "raw_response_metadata"
        ] = response_metadata

    return result


def build_instruction(
    family: str,
    module_name: str,
) -> str:
    return f"""
Generate exactly ONE mechanism-specific CodeQL branch.

MECHANISM FAMILY:
{family}

HARD REQUIREMENTS:
1. Implement only the supplied frozen mechanism contract.
2. Do NOT generate a generic CWE-639 detector.
3. Return a CodeQL module named exactly:
   {module_name}
4. The module must expose:
   predicate result(DataFlow::Node sink)
5. The decisive_security_relation must appear in executable QL logic.
6. The required_validation_or_authorization_condition must appear in executable QL logic.
7. Comments, predicate names, traceability prose, and diagnostic strings do NOT count as implementation.
8. Do not substitute a generic user-controlled-key -> sensitive-operation flow when a stronger ownership, identity, certificate, filtering, or authentication relation is required.
9. Do not generate another mechanism family's branch.
10. Do not use repository source or facts outside the supplied branch input.
11. Do not emit imports, query metadata, or a final top-level select statement.
12. Helper predicates/classes inside the module are allowed.

Also provide a traceability JSON object with exactly these six keys:
- security_subject_or_principal
- protected_target_or_security_object
- attacker_controlled_input_or_trigger
- decisive_security_relation
- required_validation_or_authorization_condition
- security_sensitive_effect

Each key must map to:
{{
  "executable_ql_elements": ["..."],
  "implementation_summary": "..."
}}

For decisive_security_relation and
required_validation_or_authorization_condition,
executable_ql_elements must be non-empty.
"""


@tool
def submit_branch(
    mechanism_family_id: str,
    branch_code: str,
    traceability_json: str,
) -> str:
    """Submit one generated mechanism-specific CodeQL branch."""
    return "SUBMITTED"


def validate_traceability(obj):
    required = [
        "security_subject_or_principal",
        "protected_target_or_security_object",
        "attacker_controlled_input_or_trigger",
        "decisive_security_relation",
        "required_validation_or_authorization_condition",
        "security_sensitive_effect",
    ]

    if set(obj) != set(required):
        raise RuntimeError(
            "TRACEABILITY_KEYS_INVALID"
        )

    for key in required:
        value = obj[key]

        if not isinstance(value, dict):
            raise RuntimeError(
                "TRACEABILITY_ENTRY_NOT_OBJECT:"
                + key
            )

        elems = value.get(
            "executable_ql_elements"
        )

        summary = value.get(
            "implementation_summary"
        )

        if not isinstance(elems, list):
            raise RuntimeError(
                "TRACEABILITY_ELEMENTS_NOT_LIST:"
                + key
            )

        if not isinstance(summary, str) or not summary.strip():
            raise RuntimeError(
                "TRACEABILITY_SUMMARY_EMPTY:"
                + key
            )

    for key in [
        "decisive_security_relation",
        "required_validation_or_authorization_condition",
    ]:
        if not obj[key]["executable_ql_elements"]:
            raise RuntimeError(
                "DECISIVE_TRACEABILITY_EMPTY:"
                + key
            )


def validate_branch_code(
    text: str,
    module_name: str,
):
    if not re.search(
        rf"\bmodule\s+{re.escape(module_name)}\b",
        text,
    ):
        raise RuntimeError(
            "REQUIRED_MODULE_MISSING"
        )

    if not re.search(
        r"\bpredicate\s+result\s*\(\s*DataFlow::Node\s+sink\s*\)",
        text,
    ):
        raise RuntimeError(
            "REQUIRED_RESULT_INTERFACE_MISSING"
        )

    if re.search(
        r"(?m)^\s*import\s+",
        text,
    ):
        raise RuntimeError(
            "IMPORT_FORBIDDEN_IN_BRANCH"
        )

    if "@kind" in text or "@id" in text:
        raise RuntimeError(
            "QUERY_METADATA_FORBIDDEN_IN_BRANCH"
        )


def self_check():
    checks = {
        "T2_runner_exists":
            T2_RUNNER.is_file(),

        "three_families":
            len(FAMILIES) == 3,

        "one_call_per_branch":
            MODEL_CALL_BUDGET_PER_BRANCH == 1,

        "output_root_absent":
            not OUTPUT_ROOT.exists(),

        "all_inputs_exist":
            True,

        "all_inputs_match_family":
            True,

        "codeql_mappings_hidden":
            True,

        "encoded_status_hidden":
            True,

        "test_hidden":
            True,

        "T2_runner_importable":
            False,

        "original_runner_resolvable":
            False,

        "model_loader_resolvable":
            False,

        "model_name_resolvable":
            False,

        "system_prompt_resolvable":
            False,
    }

    for family in FAMILIES:
        p = (
            INPUT_ROOT
            / family
            / "branch_input.json"
        )

        if not p.is_file():
            checks[
                "all_inputs_exist"
            ] = False
            continue

        data = json.loads(
            p.read_text(
                encoding="utf-8",
                errors="replace",
            )
        )

        if (
            data.get("mechanism_family_id")
            != family
        ):
            checks[
                "all_inputs_match_family"
            ] = False

        txt = p.read_text(
            encoding="utf-8",
            errors="replace",
        )

        if '"codeql_mappings"' in txt:
            checks[
                "codeql_mappings_hidden"
            ] = False

        if '"encoded_status"' in txt:
            checks[
                "encoded_status_hidden"
            ] = False

        if (
            data.get(
                "generation_visibility_controls",
                {},
            ).get("TEST_visible")
            is not False
        ):
            checks["test_hidden"] = False

    try:
        t2 = load_t2_runner()
        checks[
            "T2_runner_importable"
        ] = True

        original = resolve_original(t2)

        checks[
            "original_runner_resolvable"
        ] = True

        resolve_model_loader(
            t2,
            original,
        )

        checks[
            "model_loader_resolvable"
        ] = True

        get_model_name(
            t2,
            original,
        )

        checks[
            "model_name_resolvable"
        ] = True

        get_system_prompt(
            original
        )

        checks[
            "system_prompt_resolvable"
        ] = True

    except Exception as e:
        checks[
            "runner_resolution_error"
        ] = repr(e)

    core = [
        value
        for key, value in checks.items()
        if key != "runner_resolution_error"
    ]

    return {
        "status":
            "PASS"
            if all(core)
            else "FAIL",

        "checks":
            checks,

        "model_execution":
            False,

        "codeql_execution":
            False,

        "model_call_budget_per_branch":
            1,

        "test_access":
            "FORBIDDEN",
    }


async def generate_branch(
    family: str,
):
    if family not in FAMILIES:
        raise RuntimeError(
            "UNKNOWN_MECHANISM_FAMILY"
        )

    cfg = FAMILIES[family]

    input_path = (
        INPUT_ROOT
        / family
        / "branch_input.json"
    )

    output_dir = (
        OUTPUT_ROOT
        / family
    )

    if output_dir.exists():
        raise RuntimeError(
            "BRANCH_OUTPUT_ALREADY_EXISTS_REFUSING_RERUN="
            + str(output_dir)
        )

    branch_input = json.loads(
        input_path.read_text(
            encoding="utf-8",
            errors="replace",
        )
    )

    output_dir.mkdir(
        parents=True,
        exist_ok=False,
    )

    claim = (
        output_dir
        / "MODEL_CALL_BUDGET_CLAIM.json"
    )

    claim.write_text(
        json.dumps(
            {
                "schema_version":
                    "1.0",

                "mechanism_family_id":
                    family,

                "model_call_budget_claimed":
                    1,

                "model_call_may_execute_after_this_marker":
                    True,

                "automatic_rerun_allowed":
                    False,

                "test_access":
                    "FORBIDDEN",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    t2 = load_t2_runner()
    original = resolve_original(t2)

    loader = resolve_model_loader(
        t2,
        original,
    )

    model_name = get_model_name(
        t2,
        original,
    )

    system_prompt = get_system_prompt(
        original
    )

    model = loader(
        model_name
    ).bind_tools(
        [submit_branch]
    )

    human_prompt = (
        build_instruction(
            family,
            cfg["module"],
        )
        + "\n\nFROZEN BRANCH INPUT:\n"
        + json.dumps(
            branch_input,
            indent=2,
            ensure_ascii=False,
        )
    )

    started = time.perf_counter()

    response = await model.ainvoke([
        SystemMessage(
            content=system_prompt
        ),
        HumanMessage(
            content=human_prompt
        ),
    ])

    wall = (
        time.perf_counter()
        - started
    )

    calls = (
        getattr(
            response,
            "tool_calls",
            None,
        )
        or []
    )

    if len(calls) != 1:
        raise RuntimeError(
            "EXPECTED_ONE_TOOL_CALL_GOT_"
            + str(len(calls))
        )

    call = calls[0]

    if call.get("name") != "submit_branch":
        raise RuntimeError(
            "UNEXPECTED_TOOL_CALL="
            + str(call.get("name"))
        )

    args = call.get(
        "args",
        {},
    )

    if (
        args.get(
            "mechanism_family_id"
        )
        != family
    ):
        raise RuntimeError(
            "MECHANISM_FAMILY_ID_MISMATCH"
        )

    branch_code = args[
        "branch_code"
    ]

    traceability = json.loads(
        args[
            "traceability_json"
        ]
    )

    validate_branch_code(
        branch_code,
        cfg["module"],
    )

    validate_traceability(
        traceability
    )

    code_path = (
        output_dir
        / "branch.ql"
    )

    trace_path = (
        output_dir
        / "traceability.json"
    )

    meta_path = (
        output_dir
        / "generation_metadata.json"
    )

    code_path.write_text(
        branch_code.rstrip()
        + "\n",
        encoding="utf-8",
    )

    trace_path.write_text(
        json.dumps(
            traceability,
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    metadata = {
        "schema_version":
            "1.0",

        "scope":
            "CWE-639 TRAIN ONLY",

        "stage":
            "T3_INITIAL_BRANCH_GENERATION",

        "mechanism_family_id":
            family,

        "model":
            model_name,

        "model_call_count":
            1,

        "input_path":
            str(input_path),

        "input_sha256":
            H(input_path),

        "branch_path":
            str(code_path),

        "branch_sha256":
            H(code_path),

        "traceability_path":
            str(trace_path),

        "traceability_sha256":
            H(trace_path),

        "usage":
            normalized_usage(
                response
            ),

        "wall_clock_sec":
            wall,

        "manual_query_modification":
            False,

        "codeql_execution":
            False,

        "test_access":
            "FORBIDDEN",
    }

    meta_path.write_text(
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


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--self-check",
        action="store_true",
    )

    parser.add_argument(
        "--generate-branch",
        choices=sorted(FAMILIES),
    )

    args = parser.parse_args()

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

    if args.generate_branch:
        asyncio.run(
            generate_branch(
                args.generate_branch
            )
        )
        return

    raise SystemExit(
        "Specify --self-check or --generate-branch"
    )


if __name__ == "__main__":
    main()
