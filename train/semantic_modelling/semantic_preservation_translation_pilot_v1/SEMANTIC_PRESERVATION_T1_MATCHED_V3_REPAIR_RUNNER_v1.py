#!/usr/bin/env python3

from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]

OLD_RUNNER = Path(
    '/home/ray001/codeql_cwe_expansion/stage16_temporal_generalization_gpt5/train/semantic_modelling/mechanism_first_pilot_v1/MECHANISM_FIRST_PILOT_RUNNER_v1.py'
).resolve()

RUN_ROOT = Path(
    '/home/ray001/codeql_cwe_expansion/stage16_temporal_generalization_gpt5/train/compilation_improvement/corrected_replacement_protocol_v2/replacement_qlpack/semantic_preservation_translation_runs_v1/T1_MATCHED_V3_REPAIR'
).resolve()

EVAL_ROOT = (
    RUN_ROOT
    / "query_evaluations"
)

EVALUATOR = Path(
    '/home/ray001/codeql_cwe_expansion/stage16_temporal_generalization_gpt5/train/semantic_modelling/semantic_preservation_translation_pilot_v1/SEMANTIC_PRESERVATION_T1_MATCHED_V3_EVALUATOR_v1.py'
).resolve()

SOURCE_QUERY = Path(
    '/home/ray001/codeql_cwe_expansion/stage16_temporal_generalization_gpt5/train/compilation_improvement/corrected_replacement_protocol_v2/replacement_qlpack/semantic_preservation_translation_runs_v1/T1_SEMANTIC_PRESERVATION/CWE-639/iter0.ql'
).resolve()

SOURCE_INITIAL_AGG = Path(
    '/home/ray001/codeql_cwe_expansion/stage16_temporal_generalization_gpt5/train/compilation_improvement/corrected_replacement_protocol_v2/replacement_qlpack/semantic_preservation_translation_runs_v1/T1_SEMANTIC_PRESERVATION/query_evaluations_t1_valid1/CWE-639/t1_initial/aggregate.json'
).resolve()

SHARED_MASTER = (
    RUN_ROOT
    / "shared_initial/CWE-639/iter0.ql"
)

SHARED_STATE = (
    RUN_ROOT
    / "shared_initial/CWE-639/"
      "SHARED_INITIAL_EVALUATION_STATE.json"
)

V3_QUERY0 = (
    RUN_ROOT
    / "arms/V3_LIBRARY_PLUS_AUTO_SKILL/"
      "CWE-639/queries/iter0.ql"
)

ARM_OUTCOME = (
    RUN_ROOT
    / "arms/V3_LIBRARY_PLUS_AUTO_SKILL/"
      "CWE-639/ARM_OUTCOME.json"
)

CWE = "CWE-639"
ARM = "V3_LIBRARY_PLUS_AUTO_SKILL"
MAX_REPAIRS = 4

EXPECTED_SOURCE_QUERY_SHA = (
    "c7c92c88a4ecd6e91b322ca0b06b7e34dcf099a05a720fa2cb25a71de8fb4450"
)


def H(path: Path) -> str:
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest()


def load_pilot():
    spec = importlib.util.spec_from_file_location(
        "_sp_t1_matched_v3_old_pilot",
        OLD_RUNNER,
    )

    if spec is None or spec.loader is None:
        raise RuntimeError(
            "OLD_RUNNER_IMPORT_FAILED"
        )

    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def configure():
    pilot = load_pilot()
    orig = pilot.load_original()

    orig.RUN_ROOT = RUN_ROOT
    orig.EVAL_ROOT = EVAL_ROOT
    orig.EVALUATOR = EVALUATOR

    orig.core.RUN_ROOT = RUN_ROOT

    if hasattr(orig.core, "EVAL_ROOT"):
        orig.core.EVAL_ROOT = EVAL_ROOT

    return pilot, orig


def self_check():
    checks = {}

    for name, p in [
        ("old_runner", OLD_RUNNER),
        ("evaluator", EVALUATOR),
        ("source_query", SOURCE_QUERY),
        ("source_initial_agg", SOURCE_INITIAL_AGG),
        ("shared_master", SHARED_MASTER),
        ("shared_state", SHARED_STATE),
        ("v3_query0", V3_QUERY0),
    ]:
        checks[name + "_exists"] = p.is_file()

    checks["source_query_sha_frozen"] = (
        SOURCE_QUERY.is_file()
        and H(SOURCE_QUERY)
            == EXPECTED_SOURCE_QUERY_SHA
    )

    checks["shared_master_byte_identical"] = (
        SHARED_MASTER.is_file()
        and SOURCE_QUERY.is_file()
        and SHARED_MASTER.read_bytes()
            == SOURCE_QUERY.read_bytes()
    )

    checks["v3_iter0_byte_identical"] = (
        V3_QUERY0.is_file()
        and SOURCE_QUERY.is_file()
        and V3_QUERY0.read_bytes()
            == SOURCE_QUERY.read_bytes()
    )

    checks["arm_outcome_not_started"] = (
        not ARM_OUTCOME.exists()
    )

    pilot, orig = configure()

    checks["support_arm_exact"] = (
        pilot.SUPPORT_ARM == ARM
    )

    checks["pilot_max_repairs_4"] = (
        pilot.MAX_REPAIRS == MAX_REPAIRS
    )

    checks["orig_max_repairs_4"] = (
        orig.MAX_REPAIRS == MAX_REPAIRS
    )

    checks["run_root_mapped"] = (
        orig.RUN_ROOT == RUN_ROOT
    )

    checks["core_run_root_mapped"] = (
        orig.core.RUN_ROOT == RUN_ROOT
    )

    checks["eval_root_mapped"] = (
        orig.EVAL_ROOT == EVAL_ROOT
    )

    checks["evaluator_mapped"] = (
        orig.EVALUATOR == EVALUATOR
    )

    expected_v3 = (
        orig.arm_query_path(
            CWE,
            ARM,
            0,
        )
    )

    checks["v3_path_matches_orig_helper"] = (
        expected_v3.resolve()
        == V3_QUERY0.resolve()
    )

    expected_state = (
        orig.shared_state_path(
            CWE
        )
    )

    checks["state_path_matches_orig_helper"] = (
        expected_state.resolve()
        == SHARED_STATE.resolve()
    )

    state = json.loads(
        SHARED_STATE.read_text(
            encoding="utf-8"
        )
    )

    checks["state_query_sha_matches"] = (
        state["query_sha256"]
        == EXPECTED_SOURCE_QUERY_SHA
    )

    checks["state_initial_compiled_0"] = (
        state["result"]["compiled_pair_count"]
        == 0
    )

    checks["state_train_cases_7"] = (
        state["result"]["train_case_count"]
        == 7
    )

    checks["compiler_feedback_present"] = (
        len(state["compiler_feedback"]) > 0
    )

    return {
        "status":
            "PASS"
            if all(checks.values())
            else "FAIL",
        "checks": checks,
        "run_root": str(RUN_ROOT),
        "eval_root": str(EVAL_ROOT),
        "support_arm": ARM,
        "max_repairs": MAX_REPAIRS,
        "model_execution": False,
        "codeql_execution": False,
        "test_access": "FORBIDDEN",
    }


async def run_repair():
    pilot, orig = configure()

    if ARM_OUTCOME.exists():
        raise RuntimeError(
            "ARM_OUTCOME_ALREADY_EXISTS_REFUSING_RERUN="
            + str(ARM_OUTCOME)
        )

    await orig.run_arm(
        CWE,
        ARM,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--self-check",
        action="store_true",
    )
    parser.add_argument(
        "--repair",
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
            0
            if result["status"] == "PASS"
            else 2
        )

    if args.repair:
        asyncio.run(
            run_repair()
        )
        return

    raise SystemExit(
        "Specify --self-check or --repair"
    )


if __name__ == "__main__":
    main()
