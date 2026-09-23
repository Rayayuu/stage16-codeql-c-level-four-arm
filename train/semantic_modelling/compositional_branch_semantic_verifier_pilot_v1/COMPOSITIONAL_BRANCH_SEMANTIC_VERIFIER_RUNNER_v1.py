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

BRANCH_INPUT_ROOT = (
    PILOT_ROOT
    / "branch_inputs_v1"
)

BRANCH_OUTPUT_ROOT = (
    PILOT_ROOT
    / "branch_generation_v1"
)

VERIFIER_OUTPUT_ROOT = (
    PILOT_ROOT
    / "semantic_verifier_v1"
)

OPTIONAL_FAMILY = (
    "bypass_via_missing_or_optional_identity_component"
)

CERTIFICATE_FAMILY = (
    "improper_authentication_certificate_reuse"
)

SUPPORTED_FAMILIES = {
    OPTIONAL_FAMILY:
        PILOT_ROOT
        / "T3_OPTIONAL_IDENTITY_SUCCESS_FREEZE_v1.json",

    CERTIFICATE_FAMILY:
        PILOT_ROOT
        / "T3_CERTIFICATE_SUCCESS_FREEZE_v1.json",
}

MODEL_CALL_BUDGET_PER_INITIAL_VERIFIER = 1

VERDICTS = (
    "PASS",
    "FAIL_MISSING_DECISIVE_RELATION",
    "FAIL_MISSING_VALIDATION_CONDITION",
    "FAIL_GENERIC_SURROGATE",
    "FAIL_OTHER_SEMANTIC_LOSS",
)


def H(path: Path) -> str:
    h = hashlib.sha256()

    with path.open("rb") as f:
        for chunk in iter(
            lambda: f.read(1024 * 1024),
            b"",
        ):
            h.update(chunk)

    return h.hexdigest()


def canonical_json_sha(obj) -> str:
    raw = json.dumps(
        obj,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    return hashlib.sha256(raw).hexdigest()


def load_generation_runner():
    spec = importlib.util.spec_from_file_location(
        "t3_generation_runner_v1_1",
        GEN_RUNNER,
    )

    if spec is None or spec.loader is None:
        raise RuntimeError(
            "GENERATION_RUNNER_IMPORT_SPEC_FAILED"
        )

    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    return mod


def extract_mechanism_contract(branch_input: dict):
    if (
        "mechanism_contract" in branch_input
        and isinstance(
            branch_input["mechanism_contract"],
            dict,
        )
    ):
        return branch_input["mechanism_contract"]

    candidates = [
        value
        for key, value in branch_input.items()
        if (
            "contract" in key.lower()
            and isinstance(value, dict)
        )
    ]

    if len(candidates) != 1:
        raise RuntimeError(
            "EXPECTED_EXACTLY_ONE_MECHANISM_CONTRACT"
        )

    return candidates[0]


@tool
def submit_verifier_verdict(
    mechanism_family_id: str,
    verdict: str,
    feedback: str,
) -> str:
    """Submit one semantic verifier verdict for one generated branch."""
    return "SUBMITTED"


def build_verifier_prompt(
    family: str,
    mechanism_contract: dict,
    branch_code: str,
    traceability: dict,
) -> str:
    return f"""
Act as an independent semantic verifier.

Your task is ONLY to determine whether the supplied executable CodeQL
branch faithfully implements the supplied frozen mechanism contract.

MECHANISM FAMILY:
{family}

ALLOWED INPUTS:
1. exactly one frozen mechanism contract;
2. the generated branch code;
3. the generated traceability map.

FORBIDDEN EVIDENCE:
- CVE human-reference mechanism labels;
- CodeQL hit results;
- compiler outcomes;
- vulnerable/patched result comparisons;
- TEST data;
- repository source;
- external facts.

VERIFICATION RULES:
1. Every required contract field must map to executable QL logic.
2. Comments, names, traceability prose, and diagnostic strings alone
   do NOT count as semantic implementation.
3. The decisive_security_relation must be explicit in executable QL.
4. The required_validation_or_authorization_condition must be explicit
   in executable QL.
5. A generic user-controlled-key -> sensitive-operation surrogate
   MUST fail if the contract requires a stronger ownership, identity,
   certificate, filtering, or authentication relation.
6. Judge only semantic contract preservation. Do not judge compilation.
7. Return exactly one verifier verdict.
8. feedback must identify the concrete executable relation that is
   present or missing and must be suitable for the preregistered
   single verifier-guided revision if the verdict is not PASS.

ALLOWED VERDICTS:
- PASS
- FAIL_MISSING_DECISIVE_RELATION
- FAIL_MISSING_VALIDATION_CONDITION
- FAIL_GENERIC_SURROGATE
- FAIL_OTHER_SEMANTIC_LOSS

FROZEN MECHANISM CONTRACT:
{json.dumps(mechanism_contract, indent=2, ensure_ascii=False)}

GENERATED BRANCH CODE:
```ql
{branch_code}
}

FREEZE.write_text(
json.dumps(
freeze,
indent=2,
ensure_ascii=False,
)
+ "\n",
encoding="utf-8",
)

print(f"HARNESS_SHA256={H(HARNESS)}")
print(f"SELF_CHECK_SHA256={H(SELF_CHECK)}")
print(f"FREEZE_SHA256={H(FREEZE)}")
print("VERIFIER_HARNESS_FROZEN=YES")
print(
"NEXT_ALLOWED_ACTION="
"OPTIONAL_IDENTITY_INITIAL_SEMANTIC_VERIFIER_PRECALL_GATE"
)
