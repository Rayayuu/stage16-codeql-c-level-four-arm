#!/usr/bin/env python3

from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.util
import json
import time
from pathlib import Path
from typing import Any

from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langgraph.graph import StateGraph
from langgraph.prebuilt import ToolNode


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

C_RUNNER = (
    PROJECT_ROOT
    / "scripts"
    / "run_stage16_temporal_safe_react_c.py"
)

C_STATE_HELPER = (
    EXPERIMENT_ROOT
    / "implementation"
    / "c_success_c_state_v1.py"
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
    "_frozen_stage16_c",
    C_RUNNER,
)

cstate = load_module(
    "_c_success_state",
    C_STATE_HELPER,
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


def shared_dir(
    cwe: str,
) -> Path:
    assert_target(cwe)

    return (
        RUN_ROOT
        / "shared_initial"
        / cwe
    )


def shared_query_path(
    cwe: str,
) -> Path:
    return (
        shared_dir(cwe)
        / "SHARED_C_INITIAL.ql"
    )


def shared_state_path(
    cwe: str,
) -> Path:
    return (
        shared_dir(cwe)
        / "POST_INITIAL_C_STATE.json"
    )


def shared_transcript_path(
    cwe: str,
) -> Path:
    return (
        shared_dir(cwe)
        / "SHARED_INITIAL_TRANSCRIPT.txt"
    )


def shared_cost_path(
    cwe: str,
) -> Path:
    return (
        shared_dir(cwe)
        / "SHARED_INITIAL_GENERATION_COST.json"
    )


def shared_manifest_path(
    cwe: str,
) -> Path:
    return (
        shared_dir(cwe)
        / "SHARED_INITIAL_MANIFEST.json"
    )


def token_record(
    message: AIMessage,
) -> dict[str, int]:
    usage = (
        getattr(
            message,
            "usage_metadata",
            None,
        )
        or {}
    )

    response = (
        getattr(
            message,
            "response_metadata",
            None,
        )
        or {}
    )

    raw = (
        response.get(
            "token_usage",
            {},
        )
        or {}
    )

    input_tokens = int(
        usage.get(
            "input_tokens",
            raw.get(
                "prompt_tokens",
                0,
            ),
        )
        or 0
    )

    output_tokens = int(
        usage.get(
            "output_tokens",
            raw.get(
                "completion_tokens",
                0,
            ),
        )
        or 0
    )

    total_tokens = int(
        usage.get(
            "total_tokens",
            raw.get(
                "total_tokens",
                input_tokens
                + output_tokens,
            ),
        )
        or 0
    )

    details = (
        usage.get(
            "output_token_details",
            {},
        )
        or {}
    )

    reasoning_tokens = int(
        details.get(
            "reasoning",
            (
                raw.get(
                    "completion_tokens_details",
                    {},
                )
                or {}
            ).get(
                "reasoning_tokens",
                0,
            ),
        )
        or 0
    )

    input_details = (
        usage.get(
            "input_token_details",
            {},
        )
        or {}
    )

    cached_input = int(
        input_details.get(
            "cache_read",
            (
                raw.get(
                    "prompt_tokens_details",
                    {},
                )
                or {}
            ).get(
                "cached_tokens",
                0,
            ),
        )
        or 0
    )

    return {
        "input_tokens":
            input_tokens,
        "cached_input_tokens":
            cached_input,
        "uncached_input_tokens":
            max(
                0,
                input_tokens
                - cached_input,
            ),
        "output_tokens":
            output_tokens,
        "reasoning_tokens":
            reasoning_tokens,
        "total_tokens":
            total_tokens,
        "model_call_count":
            1,
    }


def aggregate_tokens(
    messages: list[Any],
) -> dict[str, int]:
    keys = (
        "input_tokens",
        "cached_input_tokens",
        "uncached_input_tokens",
        "output_tokens",
        "reasoning_tokens",
        "total_tokens",
        "model_call_count",
    )

    out = {
        k: 0
        for k in keys
    }

    for m in messages:
        if not isinstance(
            m,
            AIMessage,
        ):
            continue

        r = token_record(
            m
        )

        for k in keys:
            out[k] += int(
                r.get(
                    k,
                    0,
                )
            )

    return out


def build_initial_tools(
    cwe: str,
):
    assert_target(cwe)

    source_tools, runtime = (
        cstate.build_source_tools(
            cwe
        )
    )

    state = {
        "written":
            False,
        "write_result":
            None,
    }

    @tool
    def write_shared_initial_query(
        query_text: str,
    ) -> dict[str, Any]:
        """
        Write exactly one fresh shared C-level initial Java CodeQL query.
        """

        if state["written"]:
            return {
                "ok": False,
                "error":
                    "SHARED_INITIAL_ALREADY_WRITTEN",
            }

        destination = (
            shared_query_path(
                cwe
            )
        )

        if destination.exists():
            return {
                "ok": False,
                "error":
                    "SHARED_INITIAL_QUERY_ALREADY_EXISTS",
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
            "scope":
                "TRAIN_ONLY",
            "evidence_level":
                "C",
            "iteration":
                0,
            "attempt_label":
                "C_initial",
            "query_path":
                str(destination),
            "query_sha256":
                sha256_file(
                    destination
                ),
        }

        state["written"] = True
        state["write_result"] = result

        return result

    return (
        [
            *source_tools,
            write_shared_initial_query,
        ],
        runtime,
        state,
    )


def initial_system_prompt() -> str:
    return (
        frozen_c.SYSTEM_PROMPT
        + """

===== SHARED INITIAL OVERRIDE =====
This execution is ONLY the shared C-level initial synthesis stage
for a controlled four-arm experiment.

The frozen C evidence and vulnerable-source exploration policy remain
unchanged.

No arm-specific intervention is available.

Do NOT evaluate the query in this stage.
Do NOT repair the query in this stage.
There is no compiler feedback in this stage.

You may use the registered bounded vulnerable-source tools when useful.

You must eventually call write_shared_initial_query exactly once with
ONE complete general CWE-level Java CodeQL query.

After that query is written, stop without attempting a repair.
"""
    )


def initial_user_input(
    cwe: str,
) -> str:
    return (
        frozen_c.build_user_input(
            cwe
        )
        + """

===== CONTROLLED SHARED C_INITIAL STAGE =====

Generate only the fresh shared C_initial query.

The four experimental arms do not yet exist from the model's
perspective.

Use A + B + the frozen bounded C vulnerable-source exploration exactly
as permitted by the original C policy.

Do not evaluate and do not repair.

Call write_shared_initial_query exactly once.
"""
    )


def build_graph(
    cwe: str,
):
    (
        tools,
        runtime,
        write_state,
    ) = build_initial_tools(
        cwe
    )

    async def call_model(
        state,
    ):
        model = (
            frozen_c.B
            .load_chat_model(
                frozen_c.MODEL
            )
            .bind_tools(
                tools
            )
        )

        response = (
            await model.ainvoke(
                [
                    {
                        "role":
                            "system",
                        "content":
                            initial_system_prompt(),
                    },
                    *state.messages,
                ]
            )
        )

        return {
            "messages":
                [response]
        }

    builder = StateGraph(
        frozen_c.B.State,
        input_schema=
            frozen_c.B.InputState,
    )

    builder.add_node(
        "call_model",
        call_model,
    )

    builder.add_node(
        "tools",
        ToolNode(tools),
    )

    builder.add_edge(
        "__start__",
        "call_model",
    )

    def route(
        state,
    ):
        last = (
            state.messages[-1]
        )

        if not isinstance(
            last,
            AIMessage,
        ):
            raise RuntimeError(
                "EXPECTED_AI_MESSAGE"
            )

        return (
            "tools"
            if last.tool_calls
            else "__end__"
        )

    builder.add_conditional_edges(
        "call_model",
        route,
    )

    builder.add_edge(
        "tools",
        "call_model",
    )

    graph = builder.compile(
        name=
            "Stage16 C Four-Arm Shared Initial"
    )

    return (
        graph,
        tools,
        runtime,
        write_state,
    )


async def run_shared_initial(
    cwe: str,
) -> None:
    assert_target(cwe)

    if not QLPACK_FILE.is_file():
        raise RuntimeError(
            "C_SUCCESS_QLPACK_MISSING"
        )

    d = shared_dir(
        cwe
    )

    if d.exists() and any(
        d.iterdir()
    ):
        raise RuntimeError(
            "SHARED_INITIAL_ARTIFACTS_ALREADY_EXIST="
            + str(d)
        )

    graph, tools, runtime, write_state = (
        build_graph(
            cwe
        )
    )

    wall_start = (
        time.perf_counter()
    )

    result = await graph.ainvoke(
        {
            "messages": [
                (
                    "user",
                    initial_user_input(
                        cwe
                    ),
                )
            ]
        },
        config={
            "recursion_limit":
                80
        },
    )

    wall_sec = round(
        time.perf_counter()
        - wall_start,
        6,
    )

    if not write_state[
        "written"
    ]:
        raise RuntimeError(
            "SHARED_INITIAL_QUERY_NOT_WRITTEN"
        )

    write_result = (
        write_state[
            "write_result"
        ]
    )

    query = Path(
        write_result[
            "query_path"
        ]
    ).resolve()

    try:
        query.relative_to(
            PACK_ROOT
        )
    except ValueError as exc:
        raise RuntimeError(
            "SHARED_INITIAL_OUTSIDE_C_SUCCESS_QLPACK"
        ) from exc

    snapshot = (
        cstate.snapshot_state(
            runtime
        )
    )

    cstate.validate_snapshot(
        cwe,
        snapshot,
    )

    d.mkdir(
        parents=True,
        exist_ok=True,
    )

    shared_state_path(
        cwe
    ).write_text(
        json.dumps(
            snapshot,
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    messages = list(
        result.get(
            "messages",
            [],
        )
    )

    shared_transcript_path(
        cwe
    ).write_text(
        "\n\n".join(
            repr(x)
            for x in messages
        )
        + "\n",
        encoding="utf-8",
    )

    cost = {
        "schema_version":
            "1.0",
        "scope":
            "TRAIN_ONLY",
        "cwe":
            cwe,
        "evidence_level":
            "C",
        "whole_agent_wall_clock_sec":
            wall_sec,
        "tokens":
            aggregate_tokens(
                messages
            ),
        "c_source_event_count":
            len(
                snapshot[
                    "events"
                ]
            ),
    }

    shared_cost_path(
        cwe
    ).write_text(
        json.dumps(
            cost,
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    manifest = {
        "schema_version":
            "1.0",
        "scope":
            "TRAIN_ONLY",
        "test_access":
            "FORBIDDEN",
        "cwe":
            cwe,
        "evidence_level":
            "C",
        "model":
            frozen_c.MODEL,
        "query_path":
            str(query),
        "query_sha256":
            sha256_file(
                query
            ),
        "post_initial_c_state_path":
            str(
                shared_state_path(
                    cwe
                )
            ),
        "post_initial_c_state_sha256":
            sha256_file(
                shared_state_path(
                    cwe
                )
            ),
        "registered_tools": [
            x.name
            for x in tools
        ],
        "max_repairs":
            frozen_c.MAX_REPAIRS,
        "max_anchor_searches_per_benchmark":
            cstate.MAX_SEARCHES,
        "max_distinct_java_files_per_benchmark":
            cstate.MAX_FILES,
        "max_source_lines_per_benchmark":
            cstate.MAX_LINES,
        "max_lines_per_read":
            cstate.MAX_LINES_PER_READ,
        "arm_specific_intervention_visible":
            False,
        "evaluated":
            False,
        "repaired":
            False,
    }

    shared_manifest_path(
        cwe
    ).write_text(
        json.dumps(
            manifest,
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    print(
        "SHARED_INITIAL_QUERY=",
        query,
    )
    print(
        "SHARED_INITIAL_SHA256=",
        sha256_file(query),
    )
    print(
        "POST_INITIAL_C_STATE=",
        shared_state_path(cwe),
    )
    print(
        "C_SOURCE_EVENTS=",
        len(snapshot["events"]),
    )
    print(
        "MODEL_WALL_SEC=",
        wall_sec,
    )
    print(
        "TOKENS=",
        json.dumps(
            cost["tokens"],
            sort_keys=True,
        ),
    )
    print(
        "TEST_ACCESSED=NO"
    )


def self_check() -> int:
    print(
        "===== FRESH C SHARED INITIAL GENERATOR SELF-CHECK ====="
    )

    print(
        "QLPACK_PRESENT=",
        "YES"
        if QLPACK_FILE.is_file()
        else "NO",
    )

    print(
        "C_RUNNER_PRESENT=",
        "YES"
        if C_RUNNER.is_file()
        else "NO",
    )

    print(
        "C_STATE_HELPER_PRESENT=",
        "YES"
        if C_STATE_HELPER.is_file()
        else "NO",
    )

    ok = (
        QLPACK_FILE.is_file()
        and C_RUNNER.is_file()
        and C_STATE_HELPER.is_file()
    )

    for cwe in TARGET_CWES:
        (
            tools,
            runtime,
            write_state,
        ) = build_initial_tools(
            cwe
        )

        names = [
            x.name
            for x in tools
        ]

        expected = [
            "search_java_anchor",
            "read_java_source_snippet",
            "write_shared_initial_query",
        ]

        if names != expected:
            ok = False

        snap = (
            cstate.snapshot_state(
                runtime
            )
        )

        cstate.validate_snapshot(
            cwe,
            snap,
        )

        print(
            f"{cwe}: "
            f"BENCHMARKS={len(snap['benchmarks'])} "
            f"TOOLS={names} "
            f"WRITE_STATE_EMPTY={'YES' if not write_state['written'] else 'NO'}"
        )

    print(
        "INITIAL_EVALUATOR_TOOL_REGISTERED=NO"
    )
    print(
        "ARM_SPECIFIC_INITIAL_ASSISTANCE=NO"
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

    if ok:
        print(
            "VERDICT=C_SHARED_INITIAL_GENERATOR_READY"
        )
        print(
            "NEXT_STAGE=RUN_ONE_FRESH_C_SHARED_INITIAL_ONLY"
        )
        return 0

    print(
        "VERDICT=C_SHARED_INITIAL_GENERATOR_CHECK_REQUIRED"
    )
    return 1


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
        "--run",
        action="store_true",
    )

    args = parser.parse_args()

    if args.self_check:
        raise SystemExit(
            self_check()
        )

    if args.run:
        if not args.cwe:
            raise RuntimeError(
                "--run requires --cwe"
            )

        asyncio.run(
            run_shared_initial(
                args.cwe
            )
        )
        return

    parser.print_help()


if __name__ == "__main__":
    main()
