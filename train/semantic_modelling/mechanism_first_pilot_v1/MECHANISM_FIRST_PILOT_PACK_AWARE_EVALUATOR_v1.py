#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(
    "/home/ray001/codeql_cwe_expansion/"
    "stage16_temporal_generalization_gpt5"
).resolve()

PACK_ROOT = (
    ROOT
    / "train/compilation_improvement/corrected_replacement_protocol_v2"
    / "replacement_qlpack"
).resolve()

PILOT_RUNS_ROOT = (
    PACK_ROOT
    / "mechanism_first_pilot_runs_v1"
).resolve()

QLPACK_FILE = PACK_ROOT / "qlpack.yml"

ORIGINAL_EVALUATOR = (
    ROOT
    / "train/compilation_improvement/four_arm_runs_v1/implementation"
    / "evaluate_four_arm_train_query_v1_2.py"
)

ALLOWED_ARMS = {
    "M0_CONTROL_CWE_FIRST",
    "M1_MECHANISM_FIRST",
}


def cli_value(flag: str) -> str:
    if flag not in sys.argv:
        raise RuntimeError("MISSING_REQUIRED_ARGUMENT=" + flag)
    i = sys.argv.index(flag)
    if i + 1 >= len(sys.argv):
        raise RuntimeError("MISSING_ARGUMENT_VALUE=" + flag)
    return sys.argv[i + 1]


def resolve_arm_from_query(query: Path) -> tuple[str, Path]:
    q = Path(query).resolve()

    try:
        rel = q.relative_to(PILOT_RUNS_ROOT)
    except ValueError as exc:
        raise RuntimeError(
            "QUERY_OUTSIDE_MECHANISM_FIRST_PILOT_RUNS=" + str(q)
        ) from exc

    if not rel.parts:
        raise RuntimeError("INVALID_EMPTY_QUERY_RELATIVE_PATH")

    arm = rel.parts[0]

    if arm not in ALLOWED_ARMS:
        raise RuntimeError(
            "INVALID_MECHANISM_FIRST_ARM_FROM_QUERY=" + arm
        )

    arm_root = (PILOT_RUNS_ROOT / arm).resolve()

    try:
        q.relative_to(arm_root)
    except ValueError as exc:
        raise RuntimeError(
            "QUERY_OUTSIDE_SELECTED_ARM=" + str(q)
        ) from exc

    return arm, arm_root


def load_original():
    spec = importlib.util.spec_from_file_location(
        "_mechanism_first_original_evaluator_v1_2",
        ORIGINAL_EVALUATOR,
    )

    if spec is None or spec.loader is None:
        raise RuntimeError(
            "FAILED_TO_LOAD_ORIGINAL_EVALUATOR"
        )

    original = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(original)
    return original


def main() -> None:
    if not QLPACK_FILE.is_file():
        raise RuntimeError(
            "MECHANISM_FIRST_QLPACK_MISSING="
            + str(QLPACK_FILE)
        )

    query = Path(cli_value("--query")).resolve()
    arm, arm_root = resolve_arm_from_query(query)

    original = load_original()

    result_root = (
        arm_root
        / "query_evaluations"
    ).resolve()

    # Infrastructure-only isolation:
    # underlying evaluator semantics and CodeQL invocation stay unchanged.
    original.EVAL_ROOT = result_root
    original.RESULT_ROOT = result_root

    original_run_codeql = original.run_codeql

    def guarded_run_codeql(
        db,
        q,
        out_csv,
        out_log,
    ):
        qp = Path(q).resolve()

        try:
            qp.relative_to(arm_root)
        except ValueError as exc:
            raise RuntimeError(
                "CODEQL_QUERY_OUTSIDE_SELECTED_PILOT_ARM="
                + str(qp)
            ) from exc

        return original_run_codeql(
            db,
            qp,
            out_csv,
            out_log,
        )

    original.run_codeql = guarded_run_codeql

    print(
        "MECHANISM_FIRST_EVALUATOR_ARM="
        + arm
    )
    print(
        "MECHANISM_FIRST_RESULT_ROOT="
        + str(result_root)
    )
    print(
        "MECHANISM_FIRST_QUERY="
        + str(query)
    )

    original.main()


if __name__ == "__main__":
    main()
