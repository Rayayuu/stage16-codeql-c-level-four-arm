#!/usr/bin/env python3

from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.util
import json
import time
from pathlib import Path

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.tools import tool


PILOT_ROOT = Path(
    "/home/ray001/codeql_cwe_expansion/stage16_temporal_generalization_gpt5/"
    "train/semantic_modelling/compositional_branch_semantic_verifier_pilot_v1"
)

GEN_RUNNER = (
    PILOT_ROOT
    / "COMPOSITIONAL_BRANCH_GENERATION_RUNNER_v1_1.py"
)

PREREG = (
    PILOT_ROOT
    / "COMPOSITIONAL_BRANCH_SEMANTIC_VERIFIER_PREREGISTRATION_v1.json"
)

INPUT_ROOT = (
    PILOT_ROOT
    / "branch_inputs_v1"
)

BRANCH_ROOT = (
    PILOT_ROOT
    / "branch_generation_v1"
)

VERIFIER_ROOT = (
    PILOT_ROOT
    / "semantic_verifier_v1"
)

OPTIONAL = (
    "bypass_via_missing_or_optional_identity_component"
)

CERTIFICATE = (
    "improper_authentication_certificate_reuse"
)

SUCCESS_FREEZES = {
    OPTIONAL:
        PILOT_ROOT
        / "T3_OPTIONAL_IDENTITY_SUCCESS_FREEZE_v1.json",

    CERTIFICATE:
        PILOT_ROOT
        / "T3_CERTIFICATE_SUCCESS_FREEZE_v1.json",
}

VERDICTS = (
    "PASS",
    "FAIL_MISSING_DECISIVE_RELATION",
    "FAIL_MISSING_VALIDATION_CONDITION",
    "FAIL_GENERIC_SURROGATE",
    "FAIL_OTHER_SEMANTIC_LOSS",
)

CONTRACT_FIELDS = {
    "security_subject_or_principal",
    "protected_target_or_security_object",
    "attacker_controlled_input_or_trigger",
    "decisive_security_relation",
    "required_validation_or_authorization_condition",
    "security_sensitive_effect",
}


def H(path: Path) -> str:
    h = hashlib.sha256()

    with path.open("rb") as f:
        for chunk in iter(
            lambda: f.read(1024 * 1024),
            b"",
        ):
            h.update(chunk)

    return h.hexdigest()


def canonical_json(obj) -> str:
    return json.dumps(
        obj,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def load_generation_runner():
    spec = importlib.util.spec_from_file_location(
        "t3_generation_runner_v1_1",
        GEN_RUNNER,
    )

    if spec is None or spec.loader is None:
        raise RuntimeError(
            "GENERATION_RUNNER_IMPORT_FAILED"
        )

    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    return mod


def extract_contract(branch_input: dict) -> dict:
    direct_keys = (
        "mechanism_contract",
        "frozen_mechanism_contract",
        "contract",
    )

    direct = []

    for key in direct_keys:
        value = branch_input.get(key)

        if isinstance(value, dict):
            direct.append(value)

    if len(direct) == 1:
        return direct[0]

    matches = []

    def visit(value):
        if isinstance(value, dict):
            if CONTRACT_FIELDS.issubset(
                set(value.keys())
            ):
                matches.append(value)

            for child in value.values():
                visit(child)

        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(branch_input)

    unique = {}

    for obj in matches:
        unique[
            hashlib.sha256(
                canonical_json(obj).encode("utf-8")
            ).hexdigest()
        ] = obj

    if len(unique) != 1:
        raise RuntimeError(
            "EXPECTED_EXACTLY_ONE_FROZEN_MECHANISM_CONTRACT_GOT_"
            + str(len(unique))
        )

    return next(iter(unique.values()))


def load_initial_material(family: str):
    if family not in SUCCESS_FREEZES:
        raise RuntimeError(
            "UNSUPPORTED_FAMILY="
            + family
        )

    freeze_path = SUCCESS_FREEZES[family]

    if not freeze_path.is_file():
        raise RuntimeError(
            "SUCCESS_FREEZE_MISSING="
            + str(freeze_path)
        )

    freeze = json.loads(
        freeze_path.read_text(
            encoding="utf-8"
        )
    )

    if (
        freeze.get("status")
        != "FROZEN_SUCCESSFUL_INITIAL_GENERATION"
    ):
        raise RuntimeError(
            "BRANCH_NOT_FROZEN_SUCCESS"
        )

    input_path = (
        INPUT_ROOT
        / family
        / "branch_input.json"
    )

    branch_path = (
        BRANCH_ROOT
        / family
        / "branch.ql"
    )

    trace_path = (
        BRANCH_ROOT
        / family
        / "traceability.json"
    )

    for label, path in (
        ("INPUT", input_path),
        ("BRANCH", branch_path),
        ("TRACE", trace_path),
    ):
        if not path.is_file():
            raise RuntimeError(
                label
                + "_MISSING="
                + str(path)
            )

    if (
        freeze.get("input_sha256")
        != H(input_path)
    ):
        raise RuntimeError(
            "INPUT_SHA_MISMATCH_WITH_SUCCESS_FREEZE"
        )

    if (
        freeze.get("branch_sha256")
        != H(branch_path)
    ):
        raise RuntimeError(
            "BRANCH_SHA_MISMATCH_WITH_SUCCESS_FREEZE"
        )

    if (
        freeze.get("traceability_sha256")
        != H(trace_path)
    ):
        raise RuntimeError(
            "TRACE_SHA_MISMATCH_WITH_SUCCESS_FREEZE"
        )

    branch_input = json.loads(
        input_path.read_text(
            encoding="utf-8"
        )
    )

    return {
        "freeze_path":
            freeze_path,

        "input_path":
            input_path,

        "contract":
            extract_contract(
                branch_input
            ),

        "branch_path":
            branch_path,

        "branch_code":
            branch_path.read_text(
                encoding="utf-8",
                errors="replace",
            ),

        "trace_path":
            trace_path,

        "traceability":
            json.loads(
                trace_path.read_text(
                    encoding="utf-8"
                )
            ),
    }


def runtime_surface():
    gen = load_generation_runner()

    t2 = gen.load_t2_runner()
    original = gen.resolve_original(t2)

    loader = gen.resolve_model_loader(
        t2,
        original,
    )

    model_name = gen.get_model_name(
        t2,
        original,
    )

    system_prompt = gen.get_system_prompt(
        original
    )

    return (
        gen,
        loader,
        model_name,
        system_prompt,
    )


@tool
def submit_verifier_verdict(
    mechanism_family_id: str,
    verdict: str,
    feedback: str,
) -> str:
    """Submit exactly one semantic-verifier verdict."""
    return "SUBMITTED"


@tool
def submit_revised_branch(
    mechanism_family_id: str,
    branch_code: str,
    traceability_json: str,
) -> str:
    """Submit exactly one verifier-guided revised CodeQL branch."""
    return "SUBMITTED"


def verifier_prompt(
    family: str,
    contract: dict,
    branch_code: str,
    traceability: dict,
) -> str:
    parts = [
        "Act as an independent semantic verifier.",
        "",
        "Judge ONLY whether the executable CodeQL branch faithfully implements the supplied frozen mechanism contract.",
        "",
        "MECHANISM FAMILY:",
        family,
        "",
        "ALLOWED INPUTS:",
        "1. one frozen mechanism contract",
        "2. generated branch code",
        "3. generated branch traceability map",
        "",
        "FORBIDDEN INPUTS:",
        "- CVE human-reference mechanism labels",
        "- CodeQL hit results",
        "- compiler outcome",
        "- vulnerable/patched result comparison",
        "- TEST data",
        "- repository source",
        "- external facts",
        "",
        "PASS RULES:",
        "1. Every required contract field must map to executable QL logic.",
        "2. Comments, names, traceability prose, and diagnostic strings alone do not count.",
        "3. decisive_security_relation must be explicit in executable QL.",
        "4. required_validation_or_authorization_condition must be explicit in executable QL.",
        "5. A generic user-controlled-key to sensitive-operation surrogate fails when the contract requires a stronger ownership, identity, certificate, filtering, or authentication relation.",
        "6. Judge semantic preservation only; do not judge compilation.",
        "",
        "ALLOWED VERDICTS:",
        "PASS",
        "FAIL_MISSING_DECISIVE_RELATION",
        "FAIL_MISSING_VALIDATION_CONDITION",
        "FAIL_GENERIC_SURROGATE",
        "FAIL_OTHER_SEMANTIC_LOSS",
        "",
        "Return exactly one submit_verifier_verdict tool call.",
        "feedback must identify the concrete executable relation present or missing.",
        "",
        "FROZEN MECHANISM CONTRACT:",
        json.dumps(
            contract,
            indent=2,
            ensure_ascii=False,
        ),
        "",
        "GENERATED BRANCH CODE:",
        branch_code,
        "",
        "GENERATED TRACEABILITY MAP:",
        json.dumps(
            traceability,
            indent=2,
            ensure_ascii=False,
        ),
    ]

    return "\n".join(parts)


def revision_prompt(
    family: str,
    contract: dict,
    branch_code: str,
    traceability: dict,
    verdict: dict,
    module_name: str,
) -> str:
    parts = [
        "Perform the single preregistered semantic verifier-guided revision.",
        "",
        "MECHANISM FAMILY:",
        family,
        "",
        "HARD RULES:",
        "1. Use only the frozen mechanism contract, current branch, current traceability map, and frozen verifier feedback supplied below.",
        "2. Repair only the semantic loss identified by the verifier.",
        "3. Do not replace the contract with a generic CWE-639 surrogate.",
        "4. Preserve the required mechanism family.",
        "5. Return module name exactly: " + module_name,
        "6. Expose predicate result(DataFlow::Node sink).",
        "7. decisive_security_relation must be executable QL.",
        "8. required_validation_or_authorization_condition must be executable QL.",
        "9. Do not emit imports, query metadata, or a top-level select.",
        "10. Do not use repository source, CodeQL results, compiler outcomes, TEST data, or external facts.",
        "11. Return exactly one submit_revised_branch tool call.",
        "",
        "FROZEN MECHANISM CONTRACT:",
        json.dumps(
            contract,
            indent=2,
            ensure_ascii=False,
        ),
        "",
        "CURRENT BRANCH:",
        branch_code,
        "",
        "CURRENT TRACEABILITY:",
        json.dumps(
            traceability,
            indent=2,
            ensure_ascii=False,
        ),
        "",
        "FROZEN INITIAL VERIFIER VERDICT:",
        json.dumps(
            verdict,
            indent=2,
            ensure_ascii=False,
        ),
    ]

    return "\n".join(parts)


def parse_single_tool_call(
    response,
    expected_name: str,
):
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

    if call.get("name") != expected_name:
        raise RuntimeError(
            "UNEXPECTED_TOOL_CALL="
            + str(call.get("name"))
        )

    return call.get(
        "args",
        {},
    )


def write_claim(
    path: Path,
    family: str,
    stage: str,
):
    path.write_text(
        json.dumps(
            {
                "schema_version":
                    "1.0",

                "scope":
                    "CWE-639 TRAIN ONLY",

                "stage":
                    stage,

                "mechanism_family_id":
                    family,

                "model_call_budget_claimed":
                    1,

                "model_call_may_execute_after_this_marker":
                    True,

                "automatic_rerun_allowed":
                    False,

                "compiler_outcome_visible":
                    False,

                "codeql_hit_results_visible":
                    False,

                "patched_vulnerable_comparison_visible":
                    False,

                "test_access":
                    "FORBIDDEN",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


async def run_verifier(
    family: str,
    reverification: bool = False,
):
    initial = load_initial_material(
        family
    )

    if reverification:
        initial_verdict_path = (
            VERIFIER_ROOT
            / family
            / "initial"
            / "verdict.json"
        )

        revision_dir = (
            VERIFIER_ROOT
            / family
            / "revision1"
        )

        branch_path = (
            revision_dir
            / "branch.ql"
        )

        trace_path = (
            revision_dir
            / "traceability.json"
        )

        if not initial_verdict_path.is_file():
            raise RuntimeError(
                "INITIAL_VERDICT_MISSING"
            )

        if (
            not branch_path.is_file()
            or not trace_path.is_file()
        ):
            raise RuntimeError(
                "REVISION_ARTIFACTS_MISSING"
            )

        input_branch = branch_path.read_text(
            encoding="utf-8",
            errors="replace",
        )

        input_trace = json.loads(
            trace_path.read_text(
                encoding="utf-8"
            )
        )

        output_dir = (
            VERIFIER_ROOT
            / family
            / "reverification1"
        )

        stage = (
            "T3_SEMANTIC_REVERIFICATION_AFTER_SINGLE_REVISION"
        )

    else:
        input_branch = initial[
            "branch_code"
        ]

        input_trace = initial[
            "traceability"
        ]

        output_dir = (
            VERIFIER_ROOT
            / family
            / "initial"
        )

        stage = (
            "T3_INITIAL_SEMANTIC_VERIFIER"
        )

    if output_dir.exists():
        raise RuntimeError(
            "VERIFIER_OUTPUT_ALREADY_EXISTS_REFUSING_RERUN="
            + str(output_dir)
        )

    output_dir.mkdir(
        parents=True,
        exist_ok=False,
    )

    contract_path = (
        output_dir
        / "frozen_contract_input.json"
    )

    claim_path = (
        output_dir
        / "MODEL_CALL_BUDGET_CLAIM.json"
    )

    contract_path.write_text(
        json.dumps(
            initial["contract"],
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    write_claim(
        claim_path,
        family,
        stage,
    )

    gen, loader, model_name, system_prompt = (
        runtime_surface()
    )

    model = loader(
        model_name
    ).bind_tools(
        [submit_verifier_verdict]
    )

    prompt = verifier_prompt(
        family,
        initial["contract"],
        input_branch,
        input_trace,
    )

    started = time.perf_counter()

    response = await model.ainvoke([
        SystemMessage(
            content=system_prompt
        ),
        HumanMessage(
            content=prompt
        ),
    ])

    wall = (
        time.perf_counter()
        - started
    )

    args = parse_single_tool_call(
        response,
        "submit_verifier_verdict",
    )

    if (
        args.get("mechanism_family_id")
        != family
    ):
        raise RuntimeError(
            "VERIFIER_FAMILY_MISMATCH"
        )

    verdict = args.get(
        "verdict"
    )

    feedback = args.get(
        "feedback"
    )

    if verdict not in VERDICTS:
        raise RuntimeError(
            "INVALID_VERDICT="
            + str(verdict)
        )

    if (
        not isinstance(
            feedback,
            str,
        )
        or not feedback.strip()
    ):
        raise RuntimeError(
            "EMPTY_VERIFIER_FEEDBACK"
        )

    verdict_path = (
        output_dir
        / "verdict.json"
    )

    metadata_path = (
        output_dir
        / "verifier_metadata.json"
    )

    verdict_obj = {
        "schema_version":
            "1.0",

        "mechanism_family_id":
            family,

        "verdict":
            verdict,

        "feedback":
            feedback.strip(),
    }

    verdict_path.write_text(
        json.dumps(
            verdict_obj,
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
            stage,

        "mechanism_family_id":
            family,

        "model":
            model_name,

        "model_call_count":
            1,

        "success_freeze_sha256":
            H(
                initial[
                    "freeze_path"
                ]
            ),

        "contract_input_sha256":
            H(contract_path),

        "input_branch_sha256":
            hashlib.sha256(
                input_branch.encode(
                    "utf-8"
                )
            ).hexdigest(),

        "input_traceability_canonical_sha256":
            hashlib.sha256(
                canonical_json(
                    input_trace
                ).encode(
                    "utf-8"
                )
            ).hexdigest(),

        "verdict_sha256":
            H(verdict_path),

        "usage":
            gen.normalized_usage(
                response
            ),

        "wall_clock_sec":
            wall,

        "compiler_outcome_visible":
            False,

        "codeql_hit_results_visible":
            False,

        "patched_vulnerable_comparison_visible":
            False,

        "manual_query_modification":
            False,

        "codeql_execution":
            False,

        "test_access":
            "FORBIDDEN",
    }

    metadata_path.write_text(
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
            {
                "verdict":
                    verdict_obj,

                "metadata":
                    metadata,
            },
            indent=2,
            ensure_ascii=False,
        )
    )


async def run_revision(
    family: str,
):
    initial = load_initial_material(
        family
    )

    initial_verifier_dir = (
        VERIFIER_ROOT
        / family
        / "initial"
    )

    verdict_path = (
        initial_verifier_dir
        / "verdict.json"
    )

    if not verdict_path.is_file():
        raise RuntimeError(
            "INITIAL_VERDICT_MISSING"
        )

    verdict = json.loads(
        verdict_path.read_text(
            encoding="utf-8"
        )
    )

    if verdict.get("verdict") == "PASS":
        raise RuntimeError(
            "REVISION_FORBIDDEN_AFTER_PASS"
        )

    revision_dir = (
        VERIFIER_ROOT
        / family
        / "revision1"
    )

    if revision_dir.exists():
        raise RuntimeError(
            "REVISION_OUTPUT_ALREADY_EXISTS_REFUSING_RERUN"
        )

    revision_dir.mkdir(
        parents=True,
        exist_ok=False,
    )

    claim_path = (
        revision_dir
        / "MODEL_CALL_BUDGET_CLAIM.json"
    )

    write_claim(
        claim_path,
        family,
        "T3_SINGLE_VERIFIER_GUIDED_REVISION",
    )

    gen, loader, model_name, system_prompt = (
        runtime_surface()
    )

    cfg = gen.FAMILIES[
        family
    ]

    model = loader(
        model_name
    ).bind_tools(
        [submit_revised_branch]
    )

    prompt = revision_prompt(
        family,
        initial["contract"],
        initial["branch_code"],
        initial["traceability"],
        verdict,
        cfg["module"],
    )

    started = time.perf_counter()

    response = await model.ainvoke([
        SystemMessage(
            content=system_prompt
        ),
        HumanMessage(
            content=prompt
        ),
    ])

    wall = (
        time.perf_counter()
        - started
    )

    args = parse_single_tool_call(
        response,
        "submit_revised_branch",
    )

    if (
        args.get("mechanism_family_id")
        != family
    ):
        raise RuntimeError(
            "REVISION_FAMILY_MISMATCH"
        )

    branch_code = args[
        "branch_code"
    ]

    traceability = json.loads(
        args[
            "traceability_json"
        ]
    )

    gen.validate_branch_code(
        branch_code,
        cfg["module"],
    )

    gen.validate_traceability(
        traceability
    )

    branch_path = (
        revision_dir
        / "branch.ql"
    )

    trace_path = (
        revision_dir
        / "traceability.json"
    )

    metadata_path = (
        revision_dir
        / "revision_metadata.json"
    )

    branch_path.write_text(
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
            "T3_SINGLE_VERIFIER_GUIDED_REVISION",

        "mechanism_family_id":
            family,

        "model":
            model_name,

        "model_call_count":
            1,

        "initial_branch_sha256":
            H(
                initial[
                    "branch_path"
                ]
            ),

        "initial_traceability_sha256":
            H(
                initial[
                    "trace_path"
                ]
            ),

        "initial_verdict_sha256":
            H(verdict_path),

        "revised_branch_sha256":
            H(branch_path),

        "revised_traceability_sha256":
            H(trace_path),

        "usage":
            gen.normalized_usage(
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

    metadata_path.write_text(
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


def self_check():
    checks = {}

    checks[
        "generation_runner_exists"
    ] = GEN_RUNNER.is_file()

    checks[
        "prereg_exists"
    ] = PREREG.is_file()

    prereg = json.loads(
        PREREG.read_text(
            encoding="utf-8"
        )
    )

    treatment = prereg[
        "treatment_design"
    ]

    verifier = treatment[
        "semantic_verifier"
    ]

    revision = treatment[
        "verifier_guided_revision"
    ]

    checks[
        "verdicts_exact"
    ] = (
        tuple(
            verifier[
                "verdicts"
            ]
        )
        == VERDICTS
    )

    checks[
        "initial_verifier_total_budget_three"
    ] = (
        verifier[
            "initial_verifier_call_budget"
        ]
        == 3
    )

    checks[
        "single_revision"
    ] = (
        revision[
            "maximum_revisions_per_branch"
        ]
        == 1
    )

    checks[
        "exactly_one_reverification"
    ] = (
        revision[
            "reverification"
        ]
        == "EXACTLY_ONE_REVERIFICATION_CALL_AFTER_A_REVISION"
    )

    checks[
        "maximum_revision_calls_three"
    ] = (
        revision[
            "maximum_revision_calls"
        ]
        == 3
    )

    checks[
        "maximum_reverification_calls_three"
    ] = (
        revision[
            "maximum_reverification_calls"
        ]
        == 3
    )

    checks[
        "maximum_total_precomposition_calls_twelve"
    ] = (
        revision[
            "maximum_total_precomposition_model_calls"
        ]
        == 12
    )

    checks[
        "optional_initial_verifier_output_absent"
    ] = not (
        VERIFIER_ROOT
        / OPTIONAL
        / "initial"
    ).exists()

    checks[
        "optional_revision_output_absent"
    ] = not (
        VERIFIER_ROOT
        / OPTIONAL
        / "revision1"
    ).exists()

    checks[
        "optional_reverification_output_absent"
    ] = not (
        VERIFIER_ROOT
        / OPTIONAL
        / "reverification1"
    ).exists()

    try:
        material = load_initial_material(
            OPTIONAL
        )

        checks[
            "optional_frozen_material_resolvable"
        ] = True

        checks[
            "contract_dict"
        ] = isinstance(
            material[
                "contract"
            ],
            dict,
        )

        checks[
            "branch_nonempty"
        ] = bool(
            material[
                "branch_code"
            ].strip()
        )

        checks[
            "traceability_dict"
        ] = isinstance(
            material[
                "traceability"
            ],
            dict,
        )

    except Exception as exc:
        checks[
            "optional_frozen_material_resolvable"
        ] = False

        checks[
            "material_resolution_error"
        ] = repr(exc)

    try:
        gen = load_generation_runner()

        t2 = gen.load_t2_runner()
        original = gen.resolve_original(
            t2
        )

        gen.resolve_model_loader(
            t2,
            original,
        )

        gen.get_model_name(
            t2,
            original,
        )

        gen.get_system_prompt(
            original
        )

        checks[
            "runtime_surface_resolvable_without_model_call"
        ] = True

    except Exception as exc:
        checks[
            "runtime_surface_resolvable_without_model_call"
        ] = False

        checks[
            "runtime_resolution_error"
        ] = repr(exc)

    core = [
        value
        for key, value in checks.items()
        if not key.endswith("_error")
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

        "semantic_verifier_execution":
            False,

        "semantic_revision_execution":
            False,

        "reverification_execution":
            False,

        "codeql_execution":
            False,

        "query_modification":
            False,

        "test_access":
            "FORBIDDEN",
    }


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--self-check",
        action="store_true",
    )

    parser.add_argument(
        "--verify-branch",
        choices=sorted(
            SUCCESS_FREEZES
        ),
    )

    parser.add_argument(
        "--revise-branch",
        choices=sorted(
            SUCCESS_FREEZES
        ),
    )

    parser.add_argument(
        "--reverify-branch",
        choices=sorted(
            SUCCESS_FREEZES
        ),
    )

    args = parser.parse_args()

    selected = sum([
        bool(args.self_check),
        args.verify_branch is not None,
        args.revise_branch is not None,
        args.reverify_branch is not None,
    ])

    if selected != 1:
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
            if result[
                "status"
            ] == "PASS"
            else 2
        )

    if args.verify_branch:
        asyncio.run(
            run_verifier(
                args.verify_branch,
                reverification=False,
            )
        )
        return

    if args.revise_branch:
        asyncio.run(
            run_revision(
                args.revise_branch
            )
        )
        return

    if args.reverify_branch:
        asyncio.run(
            run_verifier(
                args.reverify_branch,
                reverification=True,
            )
        )
        return


if __name__ == "__main__":
    main()
