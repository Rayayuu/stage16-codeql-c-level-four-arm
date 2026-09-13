#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[4]

EXPERIMENT_ROOT = (
    PROJECT_ROOT
    / "train"
    / "compilation_improvement"
    / "c_level_four_arm_success_v1"
)

PACK_ROOT = (
    EXPERIMENT_ROOT
    / "c_success_qlpack"
).resolve()

RUN_ROOT = (
    PACK_ROOT
    / "c_success_runs_v1"
).resolve()

QLPACK_FILE = (
    PACK_ROOT
    / "qlpack.yml"
)

ORIGINAL_IMPL = (
    PROJECT_ROOT
    / "train"
    / "compilation_improvement"
    / "four_arm_runs_v1"
    / "implementation"
)

ORIGINAL_EVALUATOR = (
    ORIGINAL_IMPL
    / "evaluate_four_arm_train_query_v1_2.py"
)

if not QLPACK_FILE.is_file():
    raise RuntimeError(
        "C_SUCCESS_QLPACK_MISSING="
        + str(QLPACK_FILE)
    )

sys.path.insert(
    0,
    str(ORIGINAL_IMPL),
)

spec = importlib.util.spec_from_file_location(
    "_stage16_c_success_original_evaluator",
    ORIGINAL_EVALUATOR,
)

if spec is None or spec.loader is None:
    raise RuntimeError(
        "FAILED_TO_LOAD_ORIGINAL_EVALUATOR"
    )

original = importlib.util.module_from_spec(
    spec
)

spec.loader.exec_module(
    original
)

original.EVAL_ROOT = (
    RUN_ROOT
    / "query_evaluations"
)

original.RESULT_ROOT = (
    RUN_ROOT
    / "query_evaluations"
)

_original_run_codeql = (
    original.run_codeql
)


def guarded_run_codeql(
    db,
    query,
    out_csv,
    out_log,
):
    q = Path(query).resolve()

    try:
        q.relative_to(
            PACK_ROOT
        )
    except ValueError as exc:
        raise RuntimeError(
            "C_SUCCESS_QUERY_OUTSIDE_DECLARED_QLPACK="
            + str(q)
        ) from exc

    if not QLPACK_FILE.is_file():
        raise RuntimeError(
            "C_SUCCESS_QLPACK_DISAPPEARED"
        )

    return _original_run_codeql(
        db,
        q,
        out_csv,
        out_log,
    )


original.run_codeql = (
    guarded_run_codeql
)


if __name__ == "__main__":
    original.main()
