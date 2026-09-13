#!/usr/bin/env python3

from __future__ import annotations

import argparse
import asyncio
import copy
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from langchain_core.messages import (
    AIMessage,
    HumanMessage,
    ToolMessage,
)
from langchain_core.tools import tool


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

EVAL_ROOT = (
    RUN_ROOT
    / "query_evaluations"
)

EVALUATOR = (
    EXPERIMENT_ROOT
    / "implementation"
    / "evaluate_c_success_train_query_v1.py"
)

C_STATE_HELPER = (
    EXPERIMENT_ROOT
    / "implementation"
    / "c_success_c_state_v1.py"
)

FROZEN_C_RUNNER = (
    PROJECT_ROOT
    / "scripts"
    / "run_stage16_temporal_safe_react_c.py"
)

OLD_FOUR_ARM = (
    PROJECT_ROOT
    / "train"
    / "compilation_improvement"
    / "four_arm_runs_v1"
    / "implementation"
    / "run_four_arm_compilation_experiment_v1_3.py"
)

TARGET_CWES = (
    "CWE-116",
    "CWE-284",
    "CWE-434",
    "CWE-639",
)


def load_module(
    name: str,
    path: Path,
):
    spec = importlib.util.spec_from_file_location(
        name,
        path,
    )

    if spec is None or spec.loader is None:
        raise RuntimeError(
            "MODULE_LOAD_FAILED="
            + str(path)
        )

    m = importlib.util.module_from_spec(
        spec
    )

    spec.loader.exec_module(
        m
    )

    return m


frozen_c = load_module(
    "_c_success_frozen_c",
    FROZEN_C_RUNNER,
)

old = load_module(
    "_c_success_old_four_arm",
    OLD_FOUR_ARM,
)

cstate = load_module(
    "_c_success_state_helper",
    C_STATE_HELPER,
)

core = old.core

ARMS = tuple(old.ARMS)
LIBRARY_ARMS = set(old.LIBRARY_ARMS)
SKILL_ARMS = set(old.SKILL_ARMS)

MAX_REPAIRS = 4
MAX_LIBRARY_LOOKUPS_PER_REPAIR = (
    old.MAX_LIBRARY_LOOKUPS_PER_REPAIR
)
MAX_RETRIEVED_SKILLS_PER_REPAIR = (
    old.MAX_RETRIEVED_SKILLS_PER_REPAIR
)
MAX_MODEL_TURNS_PER_REPAIR = (
    old.MAX_MODEL_TURNS_PER_REPAIR
)


def sha256_file(
    path: Path,
) -> str:
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest()


def assert_target(
    cwe: str,
) -> None:
    if cwe not in TARGET_CWES:
        raise RuntimeError(
            "NON_TARGET_CWE="
            + cwe
        )


def assert_arm(
    arm: str,
) -> None:
    if arm not in ARMS:
        raise RuntimeError(
            "UNKNOWN_ARM="
            + arm
        )


def shared_root(
    cwe: str,
) -> Path:
    return (
        RUN_ROOT
        / "shared_initial"
        / cwe
    )


def shared_query(
    cwe: str,
) -> Path:
    return (
        shared_root(cwe)
        / "SHARED_C_INITIAL.ql"
    )


def shared_state(
    cwe: str,
) -> Path:
    return (
        shared_root(cwe)
        / "POST_INITIAL_C_STATE.json"
    )


def shared_manifest(
    cwe: str,
) -> Path:
    return (
        shared_root(cwe)
        / "SHARED_INITIAL_MANIFEST.json"
    )


def shared_aggregate(
    cwe: str,
) -> Path:
    return (
        EVAL_ROOT
        / cwe
        / "SHARED_C_INITIAL"
        / "aggregate.json"
    )


def arm_dir(
    cwe: str,
    arm: str,
) -> Path:
    return (
        RUN_ROOT
        / "arms"
        / cwe
        / arm
    )


def arm_query(
    cwe: str,
    arm: str,
    iteration: int,
) -> Path:
    return (
        arm_dir(
            cwe,
            arm,
        )
        / f"iter{iteration}.ql"
    )


def arm_state_path(
    cwe: str,
    arm: str,
    iteration: int,
) -> Path:
    return (
        arm_dir(
            cwe,
            arm,
        )
        / f"C_STATE_AFTER_REPAIR{iteration}.json"
    )


def outcome_path(
    cwe: str,
    arm: str,
) -> Path:
    return (
        arm_dir(
            cwe,
            arm,
        )
        / "OUTCOME.json"
    )


def repair_telemetry_path(
    cwe: str,
    arm: str,
    iteration: int,
) -> Path:
    return (
        arm_dir(
            cwe,
            arm,
        )
        / f"REPAIR{iteration}_TELEMETRY.json"
    )


def read_json(
    path: Path,
) -> dict[str, Any]:
    return json.loads(
        path.read_text(
            encoding="utf-8",
        )
    )


def write_json(
    path: Path,
    obj: Any,
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        json.dumps(
            obj,
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )


def codeql_runtime(
    aggregate: dict[str, Any],
) -> float:
    total = 0.0

    for r in aggregate.get(
        "results",
        [],
    ):
        total += float(
            r.get(
                "vulnerable_runtime_sec",
                0,
            )
            or 0
        )

        total += float(
            r.get(
                "patched_runtime_sec",
                0,
            )
            or 0
        )

    return round(
        total,
        6,
    )


def failure_counts(
    aggregate: dict[str, Any],
) -> dict[str, int]:
    rows = aggregate.get(
        "results",
        [],
    )

    return {
        "compilation_fail":
            sum(
                not bool(
                    r.get("compiled")
                )
                for r in rows
            ),

        "detection_fail":
            sum(
                bool(
                    r.get("compiled")
                )
                and int(
                    r.get(
                        "vulnerable_hits",
                        0,
                    )
                ) == 0
                for r in rows
            ),

        "discrimination_fail":
            sum(
                bool(
                    r.get("compiled")
                )
                and int(
                    r.get(
                        "vulnerable_hits",
                        0,
                    )
                ) >= 1
                and int(
                    r.get(
                        "patched_hits",
                        0,
                    )
                ) > 0
                for r in rows
            ),
    }


def compact_attempt(
    label: str,
    query: Path,
    aggregate: dict[str, Any],
) -> dict[str, Any]:
    return {
        "label":
            label,
        "query_path":
            str(query),
        "query_sha256":
            sha256_file(query),
        "train_case_count":
            aggregate.get(
                "train_case_count"
            ),
        "compiled_pair_count":
            aggregate.get(
                "compiled_pair_count"
            ),
        "successful_pair_count":
            aggregate.get(
                "successful_pair_count"
            ),
        "all_pairs_success":
            bool(
                aggregate.get(
                    "all_pairs_success"
                )
            ),
        **failure_counts(
            aggregate
        ),
        "codeql_runtime_sec":
            codeql_runtime(
                aggregate
            ),
    }


def pair_feedback(
    aggregate: dict[str, Any],
) -> list[dict[str, Any]]:
    out = []

    for r in aggregate.get(
        "results",
        [],
    ):
        out.append({
            "cve_id":
                r.get(
                    "cve_id"
                ),
            "compiled":
                bool(
                    r.get(
                        "compiled"
                    )
                ),
            "vulnerable_hits":
                int(
                    r.get(
                        "vulnerable_hits",
                        0,
                    )
                ),
            "patched_hits":
                int(
                    r.get(
                        "patched_hits",
                        0,
                    )
                ),
            "pair_success":
                bool(
                    r.get(
                        "pair_success"
                    )
                ),
        })

    return out


def compiler_feedback(
    aggregate: dict[str, Any],
) -> list[dict[str, Any]]:
    feedback = []

    for r in aggregate.get(
        "results",
        [],
    ):
        if (
            int(
                r.get(
                    "vulnerable_returncode",
                    0,
                )
            ) == 0
            and int(
                r.get(
                    "patched_returncode",
                    0,
                )
            ) == 0
        ):
            continue

        for side in (
            "vulnerable",
            "patched",
        ):
            p_raw = r.get(
                f"{side}_log"
            )

            if not p_raw:
                continue

            p = Path(
                p_raw
            )

            if not p.is_file():
                continue

            text = p.read_text(
                encoding="utf-8",
                errors="replace",
            )

            feedback.append({
                "cve_id":
                    r.get(
                        "cve_id"
                    ),
                "side":
                    side,
                "log_tail":
                    text[-3500:],
            })

            if len(
                feedback
            ) >= 4:
                return feedback

    return feedback


def flattened_feedback(
    feedback: list[dict[str, Any]],
) -> str:
    return "\n".join(
        str(
            x.get(
                "log_tail",
                "",
            )
        )
        for x in feedback
    )


def aggregate_token_records(
    records: list[dict[str, Any]],
) -> dict[str, int]:
    keys = set()

    for r in records:
        keys.update(
            r.keys()
        )

    out = {}

    for k in sorted(
        keys
    ):
        values = [
            v
            for r in records
            for v in [
                r.get(
                    k,
                    0,
                )
            ]
            if isinstance(
                v,
                (int, float),
            )
        ]

        out[k] = int(
            sum(values)
        )

    return out


def evaluate_query(
    *,
    cwe: str,
    arm: str,
    iteration: int,
    query: Path,
) -> dict[str, Any]:
    label = (
        f"{arm}_repair{iteration}"
    )

    out = (
        EVAL_ROOT
        / cwe
        / label
        / "aggregate.json"
    )

    if out.exists():
        raise RuntimeError(
            "EVALUATION_ARTIFACT_ALREADY_EXISTS="
            + str(out)
        )

    q = query.resolve()

    try:
        q.relative_to(
            PACK_ROOT
        )
    except ValueError as exc:
        raise RuntimeError(
            "QUERY_OUTSIDE_C_SUCCESS_QLPACK="
            + str(q)
        ) from exc

    proc = subprocess.run(
        [
            sys.executable,
            str(EVALUATOR),
            "--cwe",
            cwe,
            "--query",
            str(q),
            "--attempt-id",
            label,
        ],
        cwd=PROJECT_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=7200,
    )

    print(
        proc.stdout,
        end="",
    )

    if proc.returncode != 0:
        raise RuntimeError(
            "C_SUCCESS_EVALUATOR_FAILED="
            + proc.stdout[-8000:]
        )

    if not out.is_file():
        raise RuntimeError(
            "C_SUCCESS_EVALUATOR_MISSING_AGGREGATE="
            + str(out)
        )

    return read_json(
        out
    )


def repair_system_prompt() -> str:
    return (
        frozen_c.SYSTEM_PROMPT
        + """

===== C-LEVEL FOUR-ARM REPAIR OVERRIDE =====

This is one repair iteration of the controlled C-level
four-arm TRAIN-only experiment.

The external harness performs evaluation after this model call.
Do NOT attempt to evaluate the query yourself.

The registered bounded vulnerable-source tools remain governed
by the original frozen C policy and remaining C budget.

The only task in this iteration is to produce exactly ONE
repaired general CWE-level Java CodeQL query by eventually
calling write_repaired_query exactly once.

Compilation is necessary but is NOT the sole objective.
The strict pair objective is:

compile AND vulnerable_hits >= 1 AND patched_hits == 0

If compilation currently fails, repair compiler-causal problems.
If compilation succeeds but detection/discrimination failures
remain, improve the same general CWE-level vulnerability
hypothesis without hardcoding individual CVEs, repositories,
paths, filenames, commits, hashes, or exploit strings.

Do not access TEST.
"""
    )


async def generate_one_repair(
    *,
    cwe: str,
    arm: str,
    iteration: int,
    current_query: Path,
    current_aggregate: dict[str, Any],
    c_snapshot: dict[str, Any],
) -> dict[str, Any]:
    assert_target(cwe)
    assert_arm(arm)

    destination = arm_query(
        cwe,
        arm,
        iteration,
    )

    if destination.exists():
        raise RuntimeError(
            "REPAIR_QUERY_ALREADY_EXISTS="
            + str(destination)
        )

    comp_feedback = (
        compiler_feedback(
            current_aggregate
        )
    )

    comp_text = (
        flattened_feedback(
            comp_feedback
        )
    )

    retrieved_skills = []

    if arm in SKILL_ARMS:
        retrieved_skills = (
            core.retrieve_skills(
                comp_text,
                limit=
                    MAX_RETRIEVED_SKILLS_PER_REPAIR,
            )
        )

    (
        source_tools,
        runtime,
    ) = cstate.build_source_tools(
        cwe,
        c_snapshot,
    )

    starting_event_count = len(
        runtime[
            "events"
        ]
    )

    tool_state = {
        "library_lookup_count":
            0,
        "written":
            False,
        "write_result":
            None,
    }

    @tool
    def lookup_codeql_java_library(
        query: str,
    ) -> dict[str, Any]:
        """
        Read-only literal lookup in installed CodeQL java-all 9.0.3.
        """

        if arm not in LIBRARY_ARMS:
            return {
                "ok":
                    False,
                "error":
                    "LIBRARY_LOOKUP_NOT_ENABLED_FOR_ARM",
            }

        if (
            tool_state[
                "library_lookup_count"
            ]
            >= MAX_LIBRARY_LOOKUPS_PER_REPAIR
        ):
            return {
                "ok":
                    False,
                "error":
                    "LIBRARY_LOOKUP_BUDGET_EXHAUSTED",
            }

        tool_state[
            "library_lookup_count"
        ] += 1

        return core.library_lookup(
            query,
            max_files=8,
            context_lines=4,
        )

    @tool
    def write_repaired_query(
        query_text: str,
    ) -> dict[str, Any]:
        """
        Write exactly one repaired CWE-level Java CodeQL query.
        """

        if tool_state[
            "written"
        ]:
            return {
                "ok":
                    False,
                "error":
                    "REPAIR_ALREADY_WRITTEN",
            }

        cleaned = (
            query_text
            .strip()
        )

        if cleaned.startswith(
            "```"
        ):
            lines = (
                cleaned
                .splitlines()
            )

            if (
                lines
                and lines[0]
                .startswith("```")
            ):
                lines = lines[1:]

            if (
                lines
                and lines[-1]
                .strip()
                .startswith("```")
            ):
                lines = lines[:-1]

            cleaned = (
                "\n".join(
                    lines
                )
                .strip()
            )

        destination.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        destination.write_text(
            cleaned + "\n",
            encoding="utf-8",
        )

        result = {
            "ok":
                True,
            "iteration":
                iteration,
            "query_path":
                str(destination),
            "query_sha256":
                sha256_file(
                    destination
                ),
        }

        tool_state[
            "written"
        ] = True

        tool_state[
            "write_result"
        ] = result

        return result

    tools = [
        *source_tools,
    ]

    if arm in LIBRARY_ARMS:
        tools.append(
            lookup_codeql_java_library
        )

    tools.append(
        write_repaired_query
    )

    intervention = []

    if arm in LIBRARY_ARMS:
        intervention.append(
            "Library-aware reasoning is enabled. "
            "You may use lookup_codeql_java_library at most "
            "2 times in this repair."
        )

    if arm in SKILL_ARMS:
        intervention.append(
            "Automatically retrieved SOURCE-side reusable "
            "compilation skills are supplied below. "
            "Retrieval remains driven only by current compiler "
            "feedback, matching the frozen four-arm semantics:\n"
            + json.dumps(
                retrieved_skills,
                indent=2,
                ensure_ascii=False,
            )
        )

    if not intervention:
        intervention.append(
            "No CodeQL library lookup and no automatically "
            "retrieved compilation skill are enabled for this arm."
        )

    prior_events = (
        c_snapshot.get(
            "events",
            [],
        )
    )

    prompt = (
        frozen_c.build_user_input(
            cwe
        )
        + "\n\n"
        + "===== CONTROLLED C-LEVEL FOUR-ARM REPAIR =====\n"
        + f"CWE: {cwe}\n"
        + f"ARM: {arm}\n"
        + f"REPAIR ITERATION: {iteration}/{MAX_REPAIRS}\n\n"

        + "===== ARM-SPECIFIC ASSISTANCE =====\n"
        + "\n\n".join(
            intervention
        )
        + "\n\n"

        + "===== CURRENT QUERY =====\n"
        + current_query.read_text(
            encoding="utf-8",
            errors="replace",
        )
        + "\n\n"

        + "===== CURRENT TRAIN PAIR FEEDBACK =====\n"
        + json.dumps(
            pair_feedback(
                current_aggregate
            ),
            indent=2,
            ensure_ascii=False,
        )
        + "\n\n"

        + "===== CURRENT COMPILER FEEDBACK =====\n"
        + json.dumps(
            comp_feedback,
            indent=2,
            ensure_ascii=False,
        )
        + "\n\n"

        + "===== PRIOR C-SOURCE TOOL OBSERVATIONS =====\n"
        + json.dumps(
            prior_events,
            indent=2,
            ensure_ascii=False,
        )
        + "\n\n"

        + "Use bounded C vulnerable-source tools only when useful "
        + "and within the inherited remaining budget. "
        + "Eventually call write_repaired_query exactly once."
    )

    model = (
        frozen_c.B
        .load_chat_model(
            frozen_c.MODEL
        )
        .bind_tools(
            tools
        )
    )

    tool_map = {
        t.name: t
        for t in tools
    }

    messages: list[Any] = [
        HumanMessage(
            content=prompt
        )
    ]

    token_records = []

    wall_start = (
        time.perf_counter()
    )

    for turn in range(
        MAX_MODEL_TURNS_PER_REPAIR
    ):
        response = await model.ainvoke(
            [
                {
                    "role":
                        "system",
                    "content":
                        repair_system_prompt(),
                },
                *messages,
            ]
        )

        token_records.append(
            core.token_record_from_ai_message(
                response
            )
        )

        messages.append(
            response
        )

        calls = (
            response.tool_calls
            or []
        )

        if not calls:
            raise RuntimeError(
                "REPAIR_MODEL_RETURNED_NO_TOOL_CALL"
            )

        for idx, call in enumerate(
            calls
        ):
            name = call.get(
                "name"
            )

            if name not in tool_map:
                raise RuntimeError(
                    "UNREGISTERED_TOOL_CALL="
                    + str(name)
                )

            args = (
                call.get(
                    "args",
                    {}
                )
                or {}
            )

            result = tool_map[
                name
            ].invoke(
                args
            )

            messages.append(
                ToolMessage(
                    content=json.dumps(
                        result,
                        ensure_ascii=False,
                    ),
                    tool_call_id=
                        call.get(
                            "id"
                        )
                        or f"call_{turn}_{idx}",
                    name=name,
                )
            )

        if tool_state[
            "written"
        ]:
            break

    wall_sec = round(
        time.perf_counter()
        - wall_start,
        6,
    )

    if not tool_state[
        "written"
    ]:
        raise RuntimeError(
            "REPAIR_QUERY_NOT_WRITTEN_WITHIN_MODEL_TURN_BUDGET"
        )

    new_snapshot = (
        cstate.snapshot_state(
            runtime
        )
    )

    cstate.validate_snapshot(
        cwe,
        new_snapshot,
    )

    telemetry = {
        "schema_version":
            "1.0",
        "scope":
            "TRAIN_ONLY",
        "test_access":
            "FORBIDDEN",
        "cwe":
            cwe,
        "arm":
            arm,
        "iteration":
            iteration,
        "query_path":
            tool_state[
                "write_result"
            ][
                "query_path"
            ],
        "query_sha256":
            tool_state[
                "write_result"
            ][
                "query_sha256"
            ],
        "tokens":
            aggregate_token_records(
                token_records
            ),
        "model_wall_clock_sec":
            wall_sec,
        "library_lookup_count":
            int(
                tool_state[
                    "library_lookup_count"
                ]
            ),
        "retrieved_skill_count":
            len(
                retrieved_skills
            ),
        "retrieved_skill_ids": [
            s.get(
                "skill_id"
            )
            for s in retrieved_skills
        ],
        "c_source_events_before":
            starting_event_count,
        "c_source_events_after":
            len(
                new_snapshot[
                    "events"
                ]
            ),
        "c_source_events_this_repair":
            len(
                new_snapshot[
                    "events"
                ]
            )
            - starting_event_count,
        "compiler_feedback_entry_count":
            len(
                comp_feedback
            ),
    }

    return {
        "query":
            destination,
        "snapshot":
            new_snapshot,
        "telemetry":
            telemetry,
    }


async def run_arm(
    cwe: str,
    arm: str,
) -> None:
    assert_target(cwe)
    assert_arm(arm)

    sq = shared_query(
        cwe
    )
    ss = shared_state(
        cwe
    )
    sm = shared_manifest(
        cwe
    )
    sa = shared_aggregate(
        cwe
    )

    for p in (
        sq,
        ss,
        sm,
        sa,
        EVALUATOR,
    ):
        if not p.is_file():
            raise RuntimeError(
                "REQUIRED_INPUT_MISSING="
                + str(p)
            )

    ad = arm_dir(
        cwe,
        arm,
    )

    if ad.exists():
        raise RuntimeError(
            "ARM_ARTIFACTS_ALREADY_EXIST="
            + str(ad)
        )

    ad.mkdir(
        parents=True,
        exist_ok=False,
    )

    q0 = arm_query(
        cwe,
        arm,
        0,
    )

    shutil.copyfile(
        sq,
        q0,
    )

    if (
        sha256_file(
            q0
        )
        != sha256_file(
            sq
        )
    ):
        raise RuntimeError(
            "SHARED_INITIAL_SHA_MISMATCH"
        )

    initial_snapshot = (
        read_json(
            ss
        )
    )

    snapshot = (
        cstate.clone_snapshot(
            initial_snapshot
        )
    )

    cstate.validate_snapshot(
        cwe,
        snapshot,
    )

    aggregate = read_json(
        sa
    )

    attempts = [
        compact_attempt(
            "SHARED_C_INITIAL",
            q0,
            aggregate,
        )
    ]

    repair_telemetry = []

    current_query = q0

    terminal_reason = None

    if bool(
        aggregate.get(
            "all_pairs_success"
        )
    ):
        terminal_reason = (
            "SHARED_INITIAL_ALL_PAIRS_STRICT_SUCCESS"
        )

    else:
        for iteration in range(
            1,
            MAX_REPAIRS + 1,
        ):
            repaired = (
                await generate_one_repair(
                    cwe=cwe,
                    arm=arm,
                    iteration=iteration,
                    current_query=
                        current_query,
                    current_aggregate=
                        aggregate,
                    c_snapshot=
                        snapshot,
                )
            )

            current_query = (
                repaired[
                    "query"
                ]
            )

            snapshot = (
                repaired[
                    "snapshot"
                ]
            )

            write_json(
                arm_state_path(
                    cwe,
                    arm,
                    iteration,
                ),
                snapshot,
            )

            write_json(
                repair_telemetry_path(
                    cwe,
                    arm,
                    iteration,
                ),
                repaired[
                    "telemetry"
                ],
            )

            aggregate = evaluate_query(
                cwe=cwe,
                arm=arm,
                iteration=iteration,
                query=current_query,
            )

            attempt = compact_attempt(
                f"{arm}_repair{iteration}",
                current_query,
                aggregate,
            )

            attempts.append(
                attempt
            )

            repair_telemetry.append(
                repaired[
                    "telemetry"
                ]
            )

            print(
                "ATTEMPT_SUMMARY=",
                json.dumps(
                    attempt,
                    sort_keys=True,
                ),
            )

            if bool(
                aggregate.get(
                    "all_pairs_success"
                )
            ):
                terminal_reason = (
                    "ALL_TRAIN_PAIRS_STRICT_SUCCESS"
                )
                break

        if terminal_reason is None:
            terminal_reason = (
                "REPAIR4_EXHAUSTED"
            )

    final = attempts[-1]

    best_compiled = max(
        int(
            x[
                "compiled_pair_count"
            ]
        )
        for x in attempts
    )

    best_success = max(
        int(
            x[
                "successful_pair_count"
            ]
        )
        for x in attempts
    )

    token_totals = (
        aggregate_token_records(
            [
                t[
                    "tokens"
                ]
                for t in repair_telemetry
            ]
        )
        if repair_telemetry
        else {}
    )

    outcome = {
        "schema_version":
            "1.0",
        "scope":
            "TRAIN_ONLY",
        "test_access":
            "FORBIDDEN",
        "evidence_level":
            "C",
        "cwe":
            cwe,
        "arm":
            arm,
        "shared_initial_query_sha256":
            sha256_file(
                sq
            ),
        "arm_iter0_query_sha256":
            sha256_file(
                q0
            ),
        "shared_initial_exact_bytes":
            sha256_file(
                sq
            )
            == sha256_file(
                q0
            ),
        "repair_count":
            len(
                attempts
            )
            - 1,
        "terminal_reason":
            terminal_reason,
        "attempts":
            attempts,
        "initial_compiled_pair_count":
            attempts[0][
                "compiled_pair_count"
            ],
        "initial_successful_pair_count":
            attempts[0][
                "successful_pair_count"
            ],
        "final_compiled_pair_count":
            final[
                "compiled_pair_count"
            ],
        "final_successful_pair_count":
            final[
                "successful_pair_count"
            ],
        "best_compiled_pair_count":
            best_compiled,
        "best_successful_pair_count":
            best_success,
        "final_all_pairs_success":
            final[
                "all_pairs_success"
            ],
        "final_failure_counts": {
            "compilation_fail":
                final[
                    "compilation_fail"
                ],
            "detection_fail":
                final[
                    "detection_fail"
                ],
            "discrimination_fail":
                final[
                    "discrimination_fail"
                ],
        },
        "arm_incremental_cost": {
            "tokens":
                token_totals,
            "model_wall_clock_sec":
                round(
                    sum(
                        float(
                            t[
                                "model_wall_clock_sec"
                            ]
                        )
                        for t
                        in repair_telemetry
                    ),
                    6,
                ),
            "codeql_runtime_sec":
                round(
                    sum(
                        float(
                            x[
                                "codeql_runtime_sec"
                            ]
                        )
                        for x
                        in attempts[1:]
                    ),
                    6,
                ),
            "library_lookup_count":
                sum(
                    int(
                        t[
                            "library_lookup_count"
                        ]
                    )
                    for t
                    in repair_telemetry
                ),
            "retrieved_skill_count":
                sum(
                    int(
                        t[
                            "retrieved_skill_count"
                        ]
                    )
                    for t
                    in repair_telemetry
                ),
            "c_source_events":
                sum(
                    int(
                        t[
                            "c_source_events_this_repair"
                        ]
                    )
                    for t
                    in repair_telemetry
                ),
        },
        "max_repairs":
            MAX_REPAIRS,
        "stop_rule":
            "ALL_TRAIN_PAIRS_STRICT_SUCCESS_OR_REPAIR4",
        "manual_query_editing":
            False,
        "per_cve_tuning":
            False,
    }

    write_json(
        outcome_path(
            cwe,
            arm,
        ),
        outcome,
    )

    print()
    print(
        "===== C-SUCCESS ARM OUTCOME ====="
    )
    print(
        "CWE=",
        cwe,
    )
    print(
        "ARM=",
        arm,
    )
    print(
        "REPAIR_COUNT=",
        outcome[
            "repair_count"
        ],
    )
    print(
        "FINAL_COMPILED=",
        outcome[
            "final_compiled_pair_count"
        ],
    )
    print(
        "FINAL_STRICT_SUCCESS=",
        outcome[
            "final_successful_pair_count"
        ],
    )
    print(
        "BEST_STRICT_SUCCESS=",
        outcome[
            "best_successful_pair_count"
        ],
    )
    print(
        "TERMINAL_REASON=",
        terminal_reason,
    )
    print(
        "TEST_ACCESSED=NO"
    )


def self_check() -> int:
    print(
        "===== C-SUCCESS FOUR-ARM RUNNER SELF-CHECK ====="
    )

    checks = {
        "pack_root_exists":
            PACK_ROOT.is_dir(),

        "evaluator_exists":
            EVALUATOR.is_file(),

        "c_state_helper_exists":
            C_STATE_HELPER.is_file(),

        "frozen_c_runner_exists":
            FROZEN_C_RUNNER.is_file(),

        "old_four_arm_exists":
            OLD_FOUR_ARM.is_file(),

        "target_cwes_exact":
            TARGET_CWES
            == (
                "CWE-116",
                "CWE-284",
                "CWE-434",
                "CWE-639",
            ),

        "four_arms_exact":
            ARMS
            == (
                "V0_BASELINE_COMPILER_FEEDBACK",
                "V1_LIBRARY_AWARE_REASONING",
                "V2_AUTO_SKILL_RETRIEVAL",
                "V3_LIBRARY_PLUS_AUTO_SKILL",
            ),

        "max_repairs_is_4":
            MAX_REPAIRS
            == 4,

        "library_budget_is_2":
            MAX_LIBRARY_LOOKUPS_PER_REPAIR
            == 2,

        "skill_budget_is_4":
            MAX_RETRIEVED_SKILLS_PER_REPAIR
            == 4,

        "model_turn_budget_is_6":
            MAX_MODEL_TURNS_PER_REPAIR
            == 6,

        "c_budget_matches_original":
            (
                cstate.MAX_SEARCHES
                == frozen_c.MAX_SEARCHES
                == 5
                and cstate.MAX_FILES
                == frozen_c.MAX_FILES
                == 10
                and cstate.MAX_LINES
                == frozen_c.MAX_LINES
                == 500
                and cstate.MAX_LINES_PER_READ
                == frozen_c.MAX_LINES_PER_READ
                == 50
            ),

        "test_not_in_run_root":
            "/test/"
            not in str(
                RUN_ROOT
            ).lower(),
    }

    cwe = "CWE-116"

    required_116 = [
        shared_query(cwe),
        shared_state(cwe),
        shared_manifest(cwe),
        shared_aggregate(cwe),
    ]

    checks[
        "cwe116_shared_inputs_ready"
    ] = all(
        p.is_file()
        for p in required_116
    )

    if checks[
        "cwe116_shared_inputs_ready"
    ]:
        snap = read_json(
            shared_state(
                cwe
            )
        )

        clone = (
            cstate.clone_snapshot(
                snap
            )
        )

        cstate.validate_snapshot(
            cwe,
            clone,
        )

        checks[
            "c_state_clone_exact"
        ] = (
            clone
            == snap
            and clone
            is not snap
        )

        agg = read_json(
            shared_aggregate(
                cwe
            )
        )

        checks[
            "pair_feedback_available"
        ] = (
            len(
                pair_feedback(
                    agg
                )
            )
            == int(
                agg[
                    "train_case_count"
                ]
            )
        )

        checks[
            "compiler_feedback_available"
        ] = (
            len(
                compiler_feedback(
                    agg
                )
            )
            > 0
        )

    sample_skills = (
        core.retrieve_skills(
            "could not resolve type MethodAccess "
            "hasQualifiedName getMethod",
            limit=4,
        )
    )

    checks[
        "skill_retrieval_operational"
    ] = isinstance(
        sample_skills,
        list,
    )

    sample_library = (
        core.library_lookup(
            "hasQualifiedName",
            max_files=2,
            context_lines=1,
        )
    )

    checks[
        "library_lookup_operational"
    ] = (
        sample_library.get(
            "ok"
        )
        is True
    )

    for k, v in checks.items():
        print(
            f"{k}={'PASS' if v else 'FAIL'}"
        )

    print(
        "SAMPLE_SKILL_COUNT=",
        len(
            sample_skills
        ),
    )

    print(
        "SAMPLE_LIBRARY_RESULTS=",
        len(
            sample_library.get(
                "results",
                [],
            )
        ),
    )

    print(
        "STOP_RULE="
        "ALL_TRAIN_PAIRS_STRICT_SUCCESS_OR_REPAIR4"
    )

    print(
        "FULL_COMPILATION_IS_STOP_CONDITION=NO"
    )
    print(
        "PAIR_LEVEL_TRAIN_FEEDBACK_TO_REPAIR=YES"
    )
    print(
        "C_STATE_CLONED_PER_ARM=YES"
    )
    print(
        "SKILL_RETRIEVAL_SIGNAL="
        "COMPILER_FEEDBACK_ONLY_FROZEN_SEMANTICS"
    )
    print(
        "MODEL_EXECUTION=NO"
    )
    print(
        "CODEQL_EXECUTION=NO"
    )
    print(
        "TEST_ACCESSED=NO"
    )

    ok = all(
        checks.values()
    )

    print(
        "VERDICT="
        + (
            "C_SUCCESS_FOUR_ARM_RUNNER_READY"
            if ok
            else "C_SUCCESS_FOUR_ARM_RUNNER_CHECK_REQUIRED"
        )
    )

    if ok:
        print(
            "NEXT_STAGE=RUN_CWE116_V0_FORMAL_C_SUCCESS_ARM"
        )

    return 0 if ok else 1


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--self-check",
        action="store_true",
    )

    parser.add_argument(
        "--cwe",
        choices=TARGET_CWES,
    )

    parser.add_argument(
        "--arm",
        choices=ARMS,
    )

    parser.add_argument(
        "--run-arm",
        action="store_true",
    )

    args = parser.parse_args()

    if args.self_check:
        raise SystemExit(
            self_check()
        )

    if args.run_arm:
        if not args.cwe:
            raise RuntimeError(
                "--run-arm requires --cwe"
            )

        if not args.arm:
            raise RuntimeError(
                "--run-arm requires --arm"
            )

        asyncio.run(
            run_arm(
                args.cwe,
                args.arm,
            )
        )
        return

    parser.print_help()


if __name__ == "__main__":
    main()
