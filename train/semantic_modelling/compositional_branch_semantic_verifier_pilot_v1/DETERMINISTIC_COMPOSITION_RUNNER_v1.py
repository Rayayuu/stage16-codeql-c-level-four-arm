#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(
    "/home/ray001/codeql_cwe_expansion/stage16_temporal_generalization_gpt5/"
    "train/semantic_modelling/compositional_branch_semantic_verifier_pilot_v1"
)

PREREG = (
    ROOT
    / "COMPOSITIONAL_BRANCH_SEMANTIC_VERIFIER_PREREGISTRATION_v1.json"
)

IDOR_FREEZE = (
    ROOT
    / "T3_IDOR_SINGLE_CALL_PROTOCOL_FAILURE_FREEZE_v1.json"
)

OPTIONAL_FREEZE = (
    ROOT
    / "T3_OPTIONAL_IDENTITY_FINAL_SEMANTIC_REJECTION_FREEZE_v1.json"
)

CERT_FREEZE = (
    ROOT
    / "T3_CERTIFICATE_INITIAL_VERIFIER_PASS_FREEZE_v1.json"
)

CERT_BRANCH = (
    ROOT
    / "branch_generation_v1"
    / "improper_authentication_certificate_reuse"
    / "branch.ql"
)

CERT_TRACE = (
    ROOT
    / "branch_generation_v1"
    / "improper_authentication_certificate_reuse"
    / "traceability.json"
)

OUTROOT = (
    ROOT
    / "deterministic_composition_v1"
)

FINAL_QUERY = (
    OUTROOT
    / "CWE-639_T3_DETERMINISTIC_COMPOSED.ql"
)

MANIFEST = (
    OUTROOT
    / "composition_manifest.json"
)

PRESERVATION_AUDIT = (
    OUTROOT
    / "branch_preservation_audit.json"
)

EXPECTED_SHA = {
    "prereg":
        "7b26ad8ea5945b1e3c2fd4134f71d303cdeaaea2ae9c55c8d36cbf34e861dd87",

    "idor_freeze":
        "4fa1efb5200ab3952aa254e6190cfaa1edea31731f6cc79461b445396d0e079e",

    "optional_freeze":
        "474063b7bdbf5f804cd790a03e2b6e4914f2dc778e136d05db734528ed6f54f0",

    "cert_freeze":
        "a4e6fb67fe28d48f34dea3d8dcad4a83eb54dc4cd09567620af118a359b1d7e8",

    "cert_branch":
        "d5982d4d72b403c6fa9b481b3b021f1089f760e9419e737b7a0c2637e5a35193",

    "cert_trace":
        "437859469f1e553b89719a1267485813794b5dc616ce3bc7f57ae410aecf6733",
}


COMMON_PREFIX = """/*
 * T3 deterministic composition.
 *
 * Accepted mechanism branches are inserted byte-for-byte without
 * semantic rewriting. Rejected or failed branches are intentionally
 * omitted and are not replaced by generic surrogates.
 */

import java
import semmle.code.java.dataflow.DataFlow

"""


COMMON_SUFFIX = """

from DataFlow::Node sink
where T3BranchCertificateReuse::result(sink)
select sink,
  "CWE-639 T3 accepted mechanism branch: improper_authentication_certificate_reuse."
"""


def H(path: Path) -> str:
    h = hashlib.sha256()

    with path.open("rb") as f:
        for chunk in iter(
            lambda: f.read(1024 * 1024),
            b"",
        ):
            h.update(chunk)

    return h.hexdigest()


def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_json(path: Path):
    return json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )


def verify_frozen_inputs():
    artifacts = {
        "prereg":
            PREREG,

        "idor_freeze":
            IDOR_FREEZE,

        "optional_freeze":
            OPTIONAL_FREEZE,

        "cert_freeze":
            CERT_FREEZE,

        "cert_branch":
            CERT_BRANCH,

        "cert_trace":
            CERT_TRACE,
    }

    checks = {}

    for name, path in artifacts.items():
        checks[
            name + "_exists"
        ] = path.is_file()

        if path.is_file():
            checks[
                name + "_sha_match"
            ] = (
                H(path)
                == EXPECTED_SHA[name]
            )

    if not all(checks.values()):
        return checks, False

    prereg = load_json(
        PREREG
    )

    idor = load_json(
        IDOR_FREEZE
    )

    optional = load_json(
        OPTIONAL_FREEZE
    )

    cert = load_json(
        CERT_FREEZE
    )

    composition = (
        prereg[
            "treatment_design"
        ][
            "composition"
        ]
    )

    checks[
        "composition_method_exact"
    ] = (
        composition.get("method")
        == "DETERMINISTIC_NO_MODEL_UNIFICATION"
    )

    checks[
        "composition_model_calls_zero"
    ] = (
        composition.get("model_calls")
        == 0
    )

    checks[
        "semantic_rewriting_false"
    ] = (
        composition.get(
            "semantic_rewriting_during_composition"
        )
        is False
    )

    checks[
        "manual_query_editing_false"
    ] = (
        composition.get(
            "manual_query_editing"
        )
        is False
    )

    checks[
        "idor_protocol_failure_frozen"
    ] = (
        idor.get("status")
        == "FROZEN_INITIAL_GENERATION_OUTPUT_PROTOCOL_FAILURE"
    )

    checks[
        "optional_rejected"
    ] = (
        optional.get(
            "branch_disposition"
        )
        == "UNENCODABLE_OR_REJECTED"
    )

    checks[
        "optional_composition_ineligible"
    ] = (
        optional.get(
            "executable_composition_eligible"
        )
        is False
    )

    checks[
        "optional_generic_surrogate_forbidden"
    ] = (
        optional.get(
            "generic_surrogate_substitution_allowed"
        )
        is False
    )

    checks[
        "certificate_verifier_pass"
    ] = (
        cert.get(
            "status"
        )
        == "FROZEN_INITIAL_SEMANTIC_VERIFIER_PASS"
    )

    checks[
        "certificate_composition_eligible"
    ] = (
        cert.get(
            "executable_composition_eligible"
        )
        is True
    )

    checks[
        "certificate_branch_freeze_matches"
    ] = (
        cert.get(
            "branch_sha256"
        )
        == H(CERT_BRANCH)
    )

    checks[
        "certificate_trace_freeze_matches"
    ] = (
        cert.get(
            "traceability_sha256"
        )
        == H(CERT_TRACE)
    )

    checks[
        "human_scoring_required"
    ] = (
        cert.get(
            "human_semantic_scoring_still_required_pre_codeql"
        )
        is True
    )

    checks[
        "test_forbidden_idor"
    ] = (
        idor.get(
            "test_access",
            "FORBIDDEN"
        )
        == "FORBIDDEN"
    )

    checks[
        "test_forbidden_optional"
    ] = (
        optional.get(
            "test_access"
        )
        == "FORBIDDEN"
    )

    checks[
        "test_forbidden_certificate"
    ] = (
        cert.get(
            "test_access"
        )
        == "FORBIDDEN"
    )

    return checks, all(
        checks.values()
    )


def compose_in_memory():
    source_bytes = (
        CERT_BRANCH.read_bytes()
    )

    prefix_bytes = (
        COMMON_PREFIX.encode(
            "utf-8"
        )
    )

    suffix_bytes = (
        COMMON_SUFFIX.encode(
            "utf-8"
        )
    )

    final_bytes = (
        prefix_bytes
        + source_bytes
        + suffix_bytes
    )

    first_offset = final_bytes.find(
        source_bytes
    )

    second_offset = final_bytes.find(
        source_bytes,
        first_offset + 1,
    )

    preservation = {
        "accepted_family":
            "improper_authentication_certificate_reuse",

        "source_branch_sha256":
            sha_bytes(source_bytes),

        "source_branch_size_bytes":
            len(source_bytes),

        "source_branch_occurrence_count":
            (
                1
                if first_offset >= 0
                and second_offset == -1
                else 0
            ),

        "source_branch_first_byte_offset":
            first_offset,

        "byte_for_byte_preserved":
            (
                first_offset >= 0
                and final_bytes[
                    first_offset:
                    first_offset
                    + len(source_bytes)
                ]
                == source_bytes
            ),

        "semantic_rewriting":
            False,

        "manual_query_editing":
            False,

        "model_unification":
            False,

        "generic_surrogate_inserted":
            False,
    }

    return (
        source_bytes,
        prefix_bytes,
        suffix_bytes,
        final_bytes,
        preservation,
    )


def self_check():
    checks, identity_pass = (
        verify_frozen_inputs()
    )

    checks[
        "composition_root_absent"
    ] = not OUTROOT.exists()

    try:
        (
            source,
            prefix,
            suffix,
            final_bytes,
            preservation,
        ) = compose_in_memory()

        checks[
            "dry_source_sha_exact"
        ] = (
            sha_bytes(source)
            == EXPECTED_SHA[
                "cert_branch"
            ]
        )

        checks[
            "dry_branch_occurs_exactly_once"
        ] = (
            preservation[
                "source_branch_occurrence_count"
            ]
            == 1
        )

        checks[
            "dry_branch_byte_preserved"
        ] = (
            preservation[
                "byte_for_byte_preserved"
            ]
            is True
        )

        checks[
            "dry_prefix_nonempty"
        ] = bool(prefix)

        checks[
            "dry_suffix_nonempty"
        ] = bool(suffix)

        checks[
            "dry_final_nonempty"
        ] = bool(final_bytes)

        checks[
            "dry_certificate_result_call_present"
        ] = (
            b"T3BranchCertificateReuse::result(sink)"
            in suffix
        )

    except Exception as exc:
        checks[
            "dry_compose_exception"
        ] = repr(exc)

    core_values = [
        v
        for k, v in checks.items()
        if not k.endswith(
            "_exception"
        )
    ]

    status = (
        "PASS"
        if identity_pass
        and all(core_values)
        else "FAIL"
    )

    return {
        "status":
            status,

        "checks":
            checks,

        "composition_execution":
            False,

        "model_execution":
            False,

        "codeql_execution":
            False,

        "query_modification":
            False,

        "human_semantic_scoring_execution":
            False,

        "test_access":
            "FORBIDDEN",

        "next_allowed_action":
            (
                "EXECUTE_DETERMINISTIC_COMPOSITION"
                if status == "PASS"
                else "STOP"
            ),
    }


def compose():
    checks, ok = (
        verify_frozen_inputs()
    )

    if not ok:
        raise RuntimeError(
            "FROZEN_INPUT_GATE_FAILED"
        )

    if OUTROOT.exists():
        raise RuntimeError(
            "COMPOSITION_OUTPUT_ALREADY_EXISTS_REFUSING_RERUN"
        )

    (
        source,
        prefix,
        suffix,
        final_bytes,
        preservation,
    ) = compose_in_memory()

    if (
        preservation[
            "source_branch_occurrence_count"
        ]
        != 1
    ):
        raise RuntimeError(
            "BRANCH_OCCURRENCE_COUNT_INVALID"
        )

    if not preservation[
        "byte_for_byte_preserved"
    ]:
        raise RuntimeError(
            "BRANCH_BYTE_PRESERVATION_FAILED"
        )

    OUTROOT.mkdir(
        parents=True,
        exist_ok=False,
    )

    FINAL_QUERY.write_bytes(
        final_bytes
    )

    preservation[
        "final_query_sha256"
    ] = H(FINAL_QUERY)

    preservation[
        "final_query_size_bytes"
    ] = FINAL_QUERY.stat().st_size

    preservation[
        "prefix_sha256"
    ] = sha_bytes(prefix)

    preservation[
        "suffix_sha256"
    ] = sha_bytes(suffix)

    PRESERVATION_AUDIT.write_text(
        json.dumps(
            preservation,
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    manifest = {
        "schema_version":
            "1.0",

        "stage":
            "T3_DETERMINISTIC_COMPOSITION",

        "scope":
            "CWE-639 TRAIN ONLY",

        "required_final_artifact":
            "ONE CWE-LEVEL CODEQL QUERY",

        "composition_method":
            "DETERMINISTIC_NO_MODEL_UNIFICATION",

        "model_calls":
            0,

        "semantic_rewriting_during_composition":
            False,

        "manual_query_editing":
            False,

        "accepted_families": [
            "improper_authentication_certificate_reuse"
        ],

        "rejected_or_failed_families": [
            {
                "family":
                    "idor_user_controlled_identifier_to_resource_operation",

                "disposition":
                    "INITIAL_GENERATION_OUTPUT_PROTOCOL_FAILURE",
            },
            {
                "family":
                    "bypass_via_missing_or_optional_identity_component",

                "disposition":
                    "UNENCODABLE_OR_REJECTED",
            },
        ],

        "generic_surrogate_inserted":
            False,

        "accepted_branch_source_sha256":
            H(CERT_BRANCH),

        "accepted_branch_traceability_sha256":
            H(CERT_TRACE),

        "final_query_path":
            str(FINAL_QUERY),

        "final_query_sha256":
            H(FINAL_QUERY),

        "branch_preservation_audit_path":
            str(PRESERVATION_AUDIT),

        "branch_preservation_audit_sha256":
            H(PRESERVATION_AUDIT),

        "human_semantic_scoring_required_before_codeql":
            True,

        "codeql_execution":
            False,

        "test_access":
            "FORBIDDEN",

        "next_allowed_action":
            "AUDIT_DETERMINISTIC_COMPOSITION_AND_PREPARE_HUMAN_SEMANTIC_SCORING",
    }

    MANIFEST.write_text(
        json.dumps(
            manifest,
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    print(
        json.dumps(
            manifest,
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
        "--compose",
        action="store_true",
    )

    args = parser.parse_args()

    if (
        int(args.self_check)
        + int(args.compose)
        != 1
    ):
        raise SystemExit(
            "SPECIFY_EXACTLY_ONE_ACTION"
        )

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

    compose()


if __name__ == "__main__":
    main()
