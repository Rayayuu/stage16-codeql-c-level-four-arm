#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


PACK_ROOT = Path('/home/ray001/codeql_cwe_expansion/stage16_temporal_generalization_gpt5/train/compilation_improvement/corrected_replacement_protocol_v2/replacement_qlpack').resolve()

QLPACK_FILE = (
    PACK_ROOT
    / "qlpack.yml"
)

RUN_ROOT = Path('/home/ray001/codeql_cwe_expansion/stage16_temporal_generalization_gpt5/train/compilation_improvement/corrected_replacement_protocol_v2/replacement_qlpack/structured_mechanism_contract_mapping_runs_v1/T2_MATCHED_V3_REPAIR').resolve()

OUTPUT_NAMESPACE = "query_evaluations"

SOURCE_VALID1_WRAPPER = Path(
    '/home/ray001/codeql_cwe_expansion/stage16_temporal_generalization_gpt5/train/semantic_modelling/mechanism_first_pilot_v1/MECHANISM_FIRST_PILOT_PACK_AWARE_EVALUATOR_VALID1_v1.py'
).resolve()


def cli_value(flag: str) -> str:
    if flag not in sys.argv:
        raise RuntimeError(
            "MISSING_REQUIRED_CLI_FLAG="
            + flag
        )

    i = sys.argv.index(flag)

    if i + 1 >= len(sys.argv):
        raise RuntimeError(
            "MISSING_REQUIRED_CLI_VALUE="
            + flag
        )

    return sys.argv[i + 1]


def load_source_wrapper():
    spec = importlib.util.spec_from_file_location(
        "_sp_t1_matched_v3_source_valid1",
        SOURCE_VALID1_WRAPPER,
    )

    if spec is None or spec.loader is None:
        raise RuntimeError(
            "SOURCE_VALID1_IMPORT_FAILED="
            + str(SOURCE_VALID1_WRAPPER)
        )

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_original():
    source = load_source_wrapper()
    return source.load_original()


def main() -> None:
    if not QLPACK_FILE.is_file():
        raise RuntimeError(
            "MATCHED_V3_QLPACK_MISSING="
            + str(QLPACK_FILE)
        )

    query = Path(
        cli_value("--query")
    ).resolve()

    try:
        query.relative_to(RUN_ROOT)
    except ValueError as exc:
        raise RuntimeError(
            "MATCHED_V3_QUERY_OUTSIDE_RUN_ROOT="
            + str(query)
        ) from exc

    result_root = (
        RUN_ROOT
        / OUTPUT_NAMESPACE
    ).resolve()

    original = load_original()

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
            qp.relative_to(RUN_ROOT)
        except ValueError as exc:
            raise RuntimeError(
                "CODEQL_QUERY_OUTSIDE_MATCHED_V3_RUN_ROOT="
                + str(qp)
            ) from exc

        return original_run_codeql(
            db,
            qp,
            out_csv,
            out_log,
        )

    original.run_codeql = guarded_run_codeql

    print("SEMANTIC_PRESERVATION_EVALUATOR=T2_MATCHED_V3_REPAIR")
    print("SEMANTIC_PRESERVATION_RESULT_ROOT=" + str(result_root))
    print("SEMANTIC_PRESERVATION_QUERY=" + str(query))

    original.main()


if __name__ == "__main__":
    main()
