#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]

PACK_ROOT = Path('/home/ray001/codeql_cwe_expansion/stage16_temporal_generalization_gpt5/train/compilation_improvement/corrected_replacement_protocol_v2/replacement_qlpack').resolve()

QLPACK_FILE = (
    PACK_ROOT
    / "qlpack.yml"
)

T1_RUN_ROOT = Path('/home/ray001/codeql_cwe_expansion/stage16_temporal_generalization_gpt5/train/compilation_improvement/corrected_replacement_protocol_v2/replacement_qlpack/structured_mechanism_contract_mapping_runs_v1/T2_STRUCTURED_CONTRACT_MAPPING').resolve()

OUTPUT_NAMESPACE = "query_evaluations_t2_valid1"

SOURCE_WRAPPER = Path('/home/ray001/codeql_cwe_expansion/stage16_temporal_generalization_gpt5/train/semantic_modelling/mechanism_first_pilot_v1/MECHANISM_FIRST_PILOT_PACK_AWARE_EVALUATOR_VALID1_v1.py').resolve()


def cli_value(flag: str) -> str:
    if flag not in sys.argv:
        raise RuntimeError(
            "MISSING_REQUIRED_CLI_FLAG=" + flag
        )

    i = sys.argv.index(flag)

    if i + 1 >= len(sys.argv):
        raise RuntimeError(
            "MISSING_REQUIRED_CLI_VALUE=" + flag
        )

    return sys.argv[i + 1]


def load_source_wrapper():
    spec = importlib.util.spec_from_file_location(
        "_semantic_preservation_source_valid1_wrapper",
        SOURCE_WRAPPER,
    )

    if spec is None or spec.loader is None:
        raise RuntimeError(
            "SOURCE_WRAPPER_IMPORT_FAILED="
            + str(SOURCE_WRAPPER)
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
            "T1_QLPACK_MISSING="
            + str(QLPACK_FILE)
        )

    query = Path(
        cli_value("--query")
    ).resolve()

    try:
        query.relative_to(T1_RUN_ROOT)
    except ValueError as exc:
        raise RuntimeError(
            "T1_QUERY_OUTSIDE_ALLOWED_RUN_ROOT="
            + str(query)
        ) from exc

    result_root = (
        T1_RUN_ROOT
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
            qp.relative_to(T1_RUN_ROOT)
        except ValueError as exc:
            raise RuntimeError(
                "CODEQL_QUERY_OUTSIDE_T1_RUN_ROOT="
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
        "SEMANTIC_PRESERVATION_EVALUATOR=T1"
    )
    print(
        "SEMANTIC_PRESERVATION_OUTPUT_NAMESPACE="
        + OUTPUT_NAMESPACE
    )
    print(
        "SEMANTIC_PRESERVATION_RESULT_ROOT="
        + str(result_root)
    )
    print(
        "SEMANTIC_PRESERVATION_QUERY="
        + str(query)
    )
    print(
        "SEMANTIC_PRESERVATION_QUERY_SHA256="
        + __import__("hashlib").sha256(
            query.read_bytes()
        ).hexdigest()
    )

    original.main()


if __name__ == "__main__":
    main()
