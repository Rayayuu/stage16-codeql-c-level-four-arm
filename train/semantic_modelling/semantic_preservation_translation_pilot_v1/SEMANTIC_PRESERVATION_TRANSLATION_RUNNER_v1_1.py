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


ROOT = Path(__file__).resolve().parents[3]

PILOT_ROOT = (
    ROOT
    / "train/semantic_modelling/"
      "semantic_preservation_translation_pilot_v1"
)

OLD_PILOT_ROOT = (
    ROOT
    / "train/semantic_modelling/"
      "mechanism_first_pilot_v1"
)

OLD_RUNNER = (
    OLD_PILOT_ROOT
    / "MECHANISM_FIRST_PILOT_RUNNER_v1.py"
)

PREREG = (
    PILOT_ROOT
    / "SEMANTIC_PRESERVATION_TRANSLATION_PREREGISTRATION_v1.json"
)

M1_PLAN = (
    OLD_PILOT_ROOT
    / "arm_outputs_v1/M1_MECHANISM_FIRST/"
      "CWE-639/planning_stage.txt"
)

SNAPSHOT = (
    OLD_PILOT_ROOT
    / "fixed_evidence_snapshot_v1/"
      "CWE-639_A_LEVEL_INPUT_v1.json"
)

OUTPUT_QUERY = (
    PILOT_ROOT
    / "t1_generation_v1/CWE-639/iter0.ql"
)

OUTPUT_META = (
    PILOT_ROOT
    / "t1_generation_v1/CWE-639/"
      "T1_TRANSLATION_GENERATION_METADATA.json"
)

CWE = "CWE-639"
MODEL_CALL_BUDGET = 1

EXPECTED = {
    "old_runner":
        "3499c92468e51894cae3b5e178461744396a31e01b49b4c264aea3493dd11a26",
    "prereg":
        "4eb518def34d3011bbe55141bcd029c21b9a64e2ea7c61bcc74238342a77cb71",
    "plan":
        "ea609259a9f8bbed4319249de29915e640fac59cf3631fc664452d092c16368f",
    "snapshot":
        "c2b12964eab7af408e3ae46b2f2bfe1a5c5f8b4aafbc1a3e38b0e510c3a760cf",
}


def H(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_old_runner():
    spec = importlib.util.spec_from_file_location(
        "_semantic_preservation_original_mechanism_runner",
        OLD_RUNNER,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("OLD_RUNNER_IMPORT_FAILED")

    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def build_translation_instruction(frozen_plan: str) -> str:
    return (
        "\n\n===== T1 SEMANTIC-PRESERVATION CODEQL TRANSLATION =====\n"
        "Use the exact frozen mechanism-first planning output below to generate "
        "exactly ONE complete CWE-level Java CodeQL query.\n\n"

        "SEMANTIC-PRESERVATION CONTRACT:\n"
        "1. Preserve every distinct mechanism family already represented in the "
        "frozen plan.\n"
        "2. For each represented family preserve its security subject/context, "
        "attacker-controlled trigger/input, protected object or security state, "
        "decisive authorization/validation/relation, and sensitive effect.\n"
        "3. Every represented mechanism family must map to at least one explicit "
        "CodeQL predicate or query branch.\n"
        "4. Multiple semantic branches inside the ONE CWE-level query are allowed "
        "and preferred when the mechanism families are heterogeneous.\n"
        "5. Do NOT collapse heterogeneous mechanisms into a generic "
        "user-controlled ID/key -> sensitive operation abstraction.\n"
        "6. Do NOT replace certificate/credential validation, authenticated-"
        "principal relations, ownership relations, sensitive-key validation, "
        "or protocol identity conditions with a generic IDOR heuristic.\n"
        "7. If a mechanism cannot be faithfully represented with available Java "
        "CodeQL APIs, preserve a conservative explicit bounded branch rather than "
        "silently substituting a generic ID/key heuristic.\n"
        "8. Do not create per-CVE queries. Produce exactly one CWE-level query "
        "applied uniformly to all TRAIN cases.\n"
        "9. Do not hard-code CVE IDs, repository names, filenames, paths, commit "
        "hashes, or exploit-specific constants.\n"
        "10. Do not access or use patch/source B/C evidence, repository source, "
        "prior CWE-639 queries/results/repair trajectories, Sept18 human semantic "
        "analysis, hit outcomes, or TEST.\n\n"

        "----- FROZEN MECHANISM-FIRST PLAN -----\n"
        + frozen_plan
        + "\n----- END FROZEN MECHANISM-FIRST PLAN -----\n\n"

        "Call write_initial_query exactly once with the complete Java CodeQL query. "
        "Do not evaluate or repair it."
    )


async def generate() -> None:
    from langchain_core.tools import tool
    from react_agent.utils import load_chat_model

    assert H(OLD_RUNNER) == EXPECTED["old_runner"]
    assert H(PREREG) == EXPECTED["prereg"]
    assert H(M1_PLAN) == EXPECTED["plan"]
    assert H(SNAPSHOT) == EXPECTED["snapshot"]

    if OUTPUT_QUERY.exists():
        raise RuntimeError(
            "T1_QUERY_ALREADY_EXISTS_REFUSING_RERUN="
            + str(OUTPUT_QUERY)
        )

    if OUTPUT_META.exists():
        raise RuntimeError(
            "T1_METADATA_ALREADY_EXISTS_REFUSING_RERUN="
            + str(OUTPUT_META)
        )

    old = load_old_runner()
    orig = old.load_original()

    base_input = old.fixed_user_input(orig)
    system_prompt = orig.base.SYSTEM_PROMPT
    frozen_plan = M1_PLAN.read_text(
        encoding="utf-8",
        errors="replace",
    )

    @tool
    def write_initial_query(query_text: str) -> dict[str, Any]:
        """Write exactly one fresh T1 semantic-preservation Java CodeQL query."""
        cleaned = query_text.strip()

        if cleaned.startswith("```"):
            lines = cleaned.splitlines()

            if lines and lines[0].startswith("```"):
                lines = lines[1:]

            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]

            cleaned = "\n".join(lines).strip()

        if not cleaned:
            raise RuntimeError("EMPTY_T1_QUERY")

        if OUTPUT_QUERY.exists():
            raise RuntimeError(
                "T1_QUERY_ALREADY_EXISTS_DURING_TOOL_CALL"
            )

        OUTPUT_QUERY.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        OUTPUT_QUERY.write_text(
            cleaned + "\n",
            encoding="utf-8",
        )

        return {
            "ok": True,
            "query_path": str(OUTPUT_QUERY),
            "query_sha256": H(OUTPUT_QUERY),
        }

    instruction = build_translation_instruction(
        frozen_plan
    )

    query_model = load_chat_model(
        orig.MODEL
    ).bind_tools(
        [write_initial_query]
    )

    start = time.perf_counter()

    response = await query_model.ainvoke([
        {
            "role": "system",
            "content": system_prompt,
        },
        {
            "role": "user",
            "content": base_input + instruction,
        },
    ])

    elapsed = round(
        time.perf_counter() - start,
        6,
    )

    calls = response.tool_calls or []

    if (
        len(calls) != 1
        or calls[0].get("name") != "write_initial_query"
    ):
        raise RuntimeError(
            "EXPECTED_EXACTLY_ONE_WRITE_INITIAL_QUERY_TOOL_CALL="
            + repr(calls)
        )

    result = write_initial_query.invoke(
        calls[0].get("args", {})
    )

    if not result.get("ok"):
        raise RuntimeError(
            "T1_QUERY_WRITE_FAILED="
            + repr(result)
        )

    parsed_usage = orig.parse_model_usage(
        response
    )

    usage = orig.core.aggregate_token_records(
        [parsed_usage]
    )

    payload = {
        "schema_version": "1.1",
        "scope": "TRAIN_ONLY",
        "pilot_cwe": CWE,
        "stage":
            "T1_SEMANTIC_PRESERVATION_TRANSLATION_GENERATION",
        "model": orig.MODEL,
        "model_call_count": 1,
        "model_call_budget": MODEL_CALL_BUDGET,
        "token_usage": usage,
        "wall_clock_sec": elapsed,
        "frozen_plan_path": str(M1_PLAN),
        "frozen_plan_sha256": H(M1_PLAN),
        "A_level_snapshot_path": str(SNAPSHOT),
        "A_level_snapshot_sha256": H(SNAPSHOT),
        "query_path": str(OUTPUT_QUERY),
        "query_sha256": H(OUTPUT_QUERY),
        "sept18_human_reference_visible": False,
        "hit_results_visible": False,
        "prior_codeql_results_visible": False,
        "patch_or_source_BC_visible": False,
        "manual_query_modification": False,
        "model_execution": True,
        "codeql_execution": False,
        "test_access": "FORBIDDEN",
    }

    OUTPUT_META.write_text(
        json.dumps(
            payload,
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    print(
        json.dumps(
            payload,
            indent=2,
            ensure_ascii=False,
        )
    )


def self_check() -> dict[str, Any]:
    checks = {}

    for name, p in [
        ("old_runner", OLD_RUNNER),
        ("prereg", PREREG),
        ("plan", M1_PLAN),
        ("snapshot", SNAPSHOT),
    ]:
        checks[name + "_exists"] = p.is_file()

    checks["old_runner_sha_frozen"] = (
        OLD_RUNNER.is_file()
        and H(OLD_RUNNER) == EXPECTED["old_runner"]
    )

    checks["prereg_sha_frozen"] = (
        PREREG.is_file()
        and H(PREREG) == EXPECTED["prereg"]
    )

    checks["plan_sha_frozen"] = (
        M1_PLAN.is_file()
        and H(M1_PLAN) == EXPECTED["plan"]
    )

    checks["snapshot_sha_frozen"] = (
        SNAPSHOT.is_file()
        and H(SNAPSHOT) == EXPECTED["snapshot"]
    )

    checks["model_call_budget_exactly_1"] = (
        MODEL_CALL_BUDGET == 1
    )

    checks["output_query_not_started"] = (
        not OUTPUT_QUERY.exists()
    )

    checks["output_metadata_not_started"] = (
        not OUTPUT_META.exists()
    )

    old = load_old_runner()
    orig = old.load_original()

    base_input = old.fixed_user_input(orig)
    frozen_plan = M1_PLAN.read_text(
        encoding="utf-8",
        errors="replace",
    )

    prompt = (
        base_input
        + build_translation_instruction(
            frozen_plan
        )
    )

    forbidden = [
        "FINAL_REPAIRED_QUERY_SEMANTIC_SCORES",
        "M0_FINAL_SEMANTIC_ALIGNMENT",
        "M1_FINAL_SEMANTIC_ALIGNMENT",
        "STRICT_SUCCESS_COUNT",
        "vulnerable_hits",
        "patched_hits",
        "query_evaluations_valid1",
        "/test/",
    ]

    for marker in forbidden:
        checks[
            "prompt_excludes_"
            + marker.replace("/", "_")
        ] = marker not in prompt

    checks["contains_exact_frozen_plan"] = (
        frozen_plan in prompt
    )

    checks["semantic_preservation_contract_present"] = (
        "SEMANTIC-PRESERVATION CONTRACT"
        in prompt
    )

    checks["generic_collapse_forbidden"] = (
        "Do NOT collapse heterogeneous mechanisms"
        in prompt
    )

    checks["multi_branch_allowed"] = (
        "Multiple semantic branches"
        in prompt
    )

    checks["one_CWE_query_required"] = (
        "Produce exactly one CWE-level query"
        in prompt
    )

    checks["test_forbidden"] = (
        "or TEST" in prompt
    )

    return {
        "status":
            "PASS"
            if all(checks.values())
            else "FAIL",
        "checks": checks,
        "model_call_budget": MODEL_CALL_BUDGET,
        "model_execution": False,
        "codeql_execution": False,
        "test_access": "FORBIDDEN",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--self-check",
        action="store_true",
    )
    parser.add_argument(
        "--generate",
        action="store_true",
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
            0 if result["status"] == "PASS" else 2
        )

    if args.generate:
        asyncio.run(generate())
        return

    raise SystemExit(
        "Specify --self-check or --generate"
    )


if __name__ == "__main__":
    main()
