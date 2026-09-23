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
    / "arm_outputs_v1/"
      "M1_MECHANISM_FIRST/"
      "CWE-639/"
      "planning_stage.txt"
)

SNAPSHOT = (
    OLD_PILOT_ROOT
    / "fixed_evidence_snapshot_v1/"
      "CWE-639_A_LEVEL_INPUT_v1.json"
)

OUTPUT_ROOT = (
    PILOT_ROOT
    / "t1_generation_v1"
)

OUTPUT_QUERY = (
    OUTPUT_ROOT
    / "CWE-639"
    / "iter0.ql"
)

OUTPUT_META = (
    OUTPUT_ROOT
    / "CWE-639"
    / "T1_TRANSLATION_GENERATION_METADATA.json"
)

CWE = "CWE-639"
MODEL_CALL_BUDGET = 1

EXPECTED = {
    "prereg":
        "4eb518def34d3011bbe55141bcd029c21b9a64e2ea7c61bcc74238342a77cb71",
    "plan":
        "ea609259a9f8bbed4319249de29915e640fac59cf3631fc664452d092c16368f",
    "snapshot":
        "c2b12964eab7af408e3ae46b2f2bfe1a5c5f8b4aafbc1a3e38b0e510c3a760cf",
    "old_runner":
        "3499c92468e51894cae3b5e178461744396a31e01b49b4c264aea3493dd11a26",
}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_old_runner():
    spec = importlib.util.spec_from_file_location(
        "_semantic_preservation_old_runner",
        OLD_RUNNER,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("OLD_RUNNER_IMPORT_SPEC_FAILED")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build_translation_prompt() -> str:
    plan_text = M1_PLAN.read_text(
        encoding="utf-8",
        errors="replace",
    )

    snapshot = json.loads(
        SNAPSHOT.read_text(
            encoding="utf-8",
            errors="replace",
        )
    )

    # A-level advisory evidence only.
    advisory_records = snapshot.get("cases", [])

    contract = """
You are translating an already-frozen mechanism-first security plan into ONE
CWE-level Java CodeQL query for CWE-639.

The objective is SEMANTIC PRESERVATION, not simplification.

Before writing CodeQL, preserve every mechanism family already present in the
frozen plan as an explicit security contract.

For each planned mechanism family, identify internally:
1. security subject or authenticated context,
2. attacker-controlled input / trigger / malformed condition,
3. protected object, credential, protocol state, or sensitive configuration,
4. decisive authorization, ownership, validation, identity, or contextual relation,
5. sensitive operation or security-relevant effect.

TRANSLATION REQUIREMENTS:
- Every represented mechanism family must map to at least one explicit CodeQL
  predicate or query branch.
- A multi-branch CWE-level query is allowed and preferred if mechanisms differ.
- Do NOT collapse heterogeneous mechanisms into one generic
  "user-controlled id/key -> sensitive operation" template.
- Do NOT replace certificate semantics, authenticated-principal relations,
  ownership relations, sensitive-key validation, or protocol identity checks
  with a generic IDOR heuristic.
- Preserve relation/validation/context predicates whenever the plan contains them.
- If a mechanism cannot be faithfully encoded with the available Java CodeQL
  library, retain a conservative explicit branch or clearly bounded predicate;
  do not silently substitute a generic ID/key heuristic.
- Produce exactly one CWE-level query applying uniformly to all TRAIN cases.
- Do not create per-CVE queries.
- Do not use CVE IDs, repository names, filenames, commit IDs, paths, or exploit
  constants in the query.
- Do not inspect or rely on patch evidence, source-level B/C evidence, historical
  target trajectories, hit results, prior CodeQL evaluation results, network
  sources, or TEST.
- Output only the complete Java CodeQL query text.
""".strip()

    return (
        "===== SEMANTIC-PRESERVATION TRANSLATION TASK =====\n"
        f"CWE: {CWE}\n\n"
        "===== TRANSLATION CONTRACT =====\n"
        + contract
        + "\n\n"
        "===== FROZEN MECHANISM-FIRST PLAN =====\n"
        + plan_text
        + "\n\n"
        "===== FROZEN A-LEVEL ADVISORY EVIDENCE =====\n"
        + json.dumps(
            advisory_records,
            indent=2,
            ensure_ascii=False,
        )
    )


async def generate() -> None:
    old = load_old_runner()

    assert sha256_file(PREREG) == EXPECTED["prereg"]
    assert sha256_file(M1_PLAN) == EXPECTED["plan"]
    assert sha256_file(SNAPSHOT) == EXPECTED["snapshot"]
    assert sha256_file(OLD_RUNNER) == EXPECTED["old_runner"]

    if OUTPUT_QUERY.exists():
        raise RuntimeError(
            "T1_OUTPUT_QUERY_ALREADY_EXISTS_REFUSING_RERUN="
            + str(OUTPUT_QUERY)
        )

    if OUTPUT_META.exists():
        raise RuntimeError(
            "T1_OUTPUT_METADATA_ALREADY_EXISTS_REFUSING_RERUN="
            + str(OUTPUT_META)
        )

    prompt = build_translation_prompt()

    # Reuse exactly the same model family/configuration machinery as the
    # frozen mechanism-first pilot.
    model = old.load_chat_model(old.MODEL)

    t0 = time.perf_counter()
    response = await model.ainvoke(prompt)
    elapsed = time.perf_counter() - t0

    text = old.extract_text(response).strip()

    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()

    if not text:
        raise RuntimeError("T1_EMPTY_QUERY")

    OUTPUT_QUERY.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    OUTPUT_QUERY.write_text(
        text + "\n",
        encoding="utf-8",
    )

    token_record = old.core.token_usage_from_response(response)

    meta = {
        "schema_version": "1.0",
        "scope": "TRAIN_ONLY",
        "pilot_cwe": CWE,
        "stage": "T1_SEMANTIC_PRESERVATION_TRANSLATION_GENERATION",
        "model": old.MODEL,
        "model_call_count": 1,
        "model_call_budget": MODEL_CALL_BUDGET,
        "wall_clock_sec": elapsed,
        "token_usage": token_record,
        "frozen_plan_path": str(M1_PLAN),
        "frozen_plan_sha256": sha256_file(M1_PLAN),
        "A_level_snapshot_path": str(SNAPSHOT),
        "A_level_snapshot_sha256": sha256_file(SNAPSHOT),
        "query_path": str(OUTPUT_QUERY),
        "query_sha256": sha256_file(OUTPUT_QUERY),
        "sept18_human_reference_visible": False,
        "hit_results_visible": False,
        "prior_codeql_results_visible": False,
        "patch_or_source_BC_visible": False,
        "test_access": "FORBIDDEN",
        "model_execution": True,
        "codeql_execution": False,
    }

    OUTPUT_META.write_text(
        json.dumps(
            meta,
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    print(json.dumps(meta, indent=2, ensure_ascii=False))


def self_check() -> dict[str, Any]:
    checks: dict[str, bool] = {}

    for name, path in [
        ("prereg", PREREG),
        ("plan", M1_PLAN),
        ("snapshot", SNAPSHOT),
        ("old_runner", OLD_RUNNER),
    ]:
        checks[name + "_exists"] = path.is_file()

    if PREREG.is_file():
        checks["prereg_sha_frozen"] = (
            sha256_file(PREREG)
            == EXPECTED["prereg"]
        )

    if M1_PLAN.is_file():
        checks["plan_sha_frozen"] = (
            sha256_file(M1_PLAN)
            == EXPECTED["plan"]
        )

    if SNAPSHOT.is_file():
        checks["snapshot_sha_frozen"] = (
            sha256_file(SNAPSHOT)
            == EXPECTED["snapshot"]
        )

    if OLD_RUNNER.is_file():
        checks["old_runner_sha_frozen"] = (
            sha256_file(OLD_RUNNER)
            == EXPECTED["old_runner"]
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

    prompt = build_translation_prompt()

    forbidden_markers = [
        "FINAL_REPAIRED_QUERY_SEMANTIC_SCORES",
        "M0_FINAL_SEMANTIC_ALIGNMENT",
        "M1_FINAL_SEMANTIC_ALIGNMENT",
        "STRICT_SUCCESS_COUNT",
        "vulnerable_hits",
        "patched_hits",
        "query_evaluations_valid1",
        "/test/",
    ]

    for marker in forbidden_markers:
        checks[
            "prompt_excludes_"
            + marker.replace("/", "_")
        ] = marker not in prompt

    checks["prompt_contains_frozen_plan"] = (
        M1_PLAN.read_text(
            encoding="utf-8",
            errors="replace",
        )
        in prompt
    )

    checks["single_CWE_level_query_required"] = (
        "Produce exactly one CWE-level query"
        in prompt
    )

    checks["generic_IDOR_collapse_explicitly_forbidden"] = (
        "Do NOT collapse heterogeneous mechanisms"
        in prompt
    )

    checks["multi_branch_allowed"] = (
        "multi-branch CWE-level query is allowed"
        in prompt
    )

    checks["test_forbidden_in_prompt"] = (
        "or TEST" in prompt
    )

    return {
        "status":
            "PASS"
            if all(checks.values())
            else "FAIL",
        "checks": checks,
        "model_call_budget": MODEL_CALL_BUDGET,
        "query_output": str(OUTPUT_QUERY),
        "metadata_output": str(OUTPUT_META),
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
        print(
            "===== T1 SEMANTIC-PRESERVATION HARNESS SELF-CHECK ====="
        )
        print("MODE=DRY_SELF_CHECK")
        print("TRAIN_ONLY=YES")
        print("TEST_ACCESS=FORBIDDEN")
        print("MODEL_EXECUTION=NO")
        print("CODEQL_EXECUTION=NO")
        print("QUERY_GENERATION=NO")
        print("QUERY_MODIFICATION=NO")

        result = self_check()

        print(
            json.dumps(
                result,
                indent=2,
                ensure_ascii=False,
            )
        )

        print(
            "HARNESS_SELF_CHECK="
            + result["status"]
        )
        print("TEST_ACCESSED=NO")

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
