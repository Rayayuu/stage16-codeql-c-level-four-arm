#!/usr/bin/env python3

from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.util
import json
from pathlib import Path


ROOT = Path('/home/ray001/codeql_cwe_expansion/stage16_temporal_generalization_gpt5')

OLD_PILOT = Path('/home/ray001/codeql_cwe_expansion/stage16_temporal_generalization_gpt5/train/semantic_modelling/mechanism_first_pilot_v1/MECHANISM_FIRST_PILOT_RUNNER_v1.py')
RUN_ROOT = Path('/home/ray001/codeql_cwe_expansion/stage16_temporal_generalization_gpt5/train/compilation_improvement/corrected_replacement_protocol_v2/replacement_qlpack/structured_mechanism_contract_mapping_runs_v1/T2_MATCHED_V3_REPAIR')
EVAL_ROOT = RUN_ROOT / "query_evaluations"
EVALUATOR = Path('/home/ray001/codeql_cwe_expansion/stage16_temporal_generalization_gpt5/train/semantic_modelling/structured_mechanism_contract_mapping_pilot_v1/STRUCTURED_MECHANISM_CONTRACT_T2_MATCHED_V3_EVALUATOR_v1.py')

CWE = "CWE-639"
ARM = "V3_LIBRARY_PLUS_AUTO_SKILL"

EXPECTED_ITER0_SHA = (
    "0f3188139935f0cec116efab018b3d0035ebd01a9fc0b81d68ae80a194ac1631"
)


def H(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def load_pilot():
    spec = importlib.util.spec_from_file_location(
        "_t2_matched_old_pilot",
        OLD_PILOT,
    )

    if spec is None or spec.loader is None:
        raise RuntimeError("OLD_PILOT_IMPORT_FAILED")

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

    return orig


def self_check():
    orig = configure()

    state_path = orig.shared_state_path(CWE)
    q0 = orig.arm_query_path(CWE, ARM, 0)
    outcome = orig.arm_run_dir(CWE, ARM) / "ARM_OUTCOME.json"

    checks = {
        "run_root_exists":
            RUN_ROOT.is_dir(),

        "evaluator_exists":
            EVALUATOR.is_file(),

        "shared_state_exists":
            state_path.is_file(),

        "v3_iter0_exists":
            q0.is_file(),

        "iter0_sha_frozen":
            q0.is_file()
            and H(q0) == EXPECTED_ITER0_SHA,

        "state_path_matches":
            state_path
            == RUN_ROOT
               / "shared_initial/CWE-639/"
                 "SHARED_INITIAL_EVALUATION_STATE.json",

        "arm_path_matches":
            q0
            == RUN_ROOT
               / "arms/V3_LIBRARY_PLUS_AUTO_SKILL/"
                 "CWE-639/queries/iter0.ql",

        "max_repairs_4":
            orig.MAX_REPAIRS == 4,

        "support_arm_present":
            ARM in orig.ARMS,

        "eval_root_mapped":
            orig.EVAL_ROOT == EVAL_ROOT,

        "evaluator_mapped":
            Path(orig.EVALUATOR).resolve()
            == EVALUATOR.resolve(),

        "arm_outcome_absent":
            not outcome.exists(),
    }

    state = json.loads(
        state_path.read_text(
            encoding="utf-8",
            errors="replace",
        )
    )

    checks["state_query_sha_matches"] = (
        state["query_sha256"]
        == EXPECTED_ITER0_SHA
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

        "checks":
            checks,

        "run_root":
            str(RUN_ROOT),

        "eval_root":
            str(EVAL_ROOT),

        "support_arm":
            ARM,

        "max_repairs":
            orig.MAX_REPAIRS,

        "model_execution":
            False,

        "codeql_execution":
            False,

        "test_access":
            "FORBIDDEN",
    }


async def repair():
    orig = configure()
    result = await orig.run_arm(
        CWE,
        ARM,
    )

    print(
        json.dumps(
            result,
            indent=2,
            ensure_ascii=False,
        )
    )


def main():
    p = argparse.ArgumentParser()

    p.add_argument(
        "--self-check",
        action="store_true",
    )

    p.add_argument(
        "--repair",
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

    if args.repair:
        asyncio.run(
            repair()
        )
        return

    raise SystemExit(
        "Specify --self-check or --repair"
    )


if __name__ == "__main__":
    main()
