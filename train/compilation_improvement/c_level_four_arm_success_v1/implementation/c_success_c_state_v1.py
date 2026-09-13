#!/usr/bin/env python3

from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
from pathlib import Path
from typing import Any

from langchain_core.tools import tool


PROJECT_ROOT = Path(__file__).resolve().parents[4]

C_RUNNER = (
    PROJECT_ROOT
    / "scripts"
    / "run_stage16_temporal_safe_react_c.py"
)

spec = importlib.util.spec_from_file_location(
    "_frozen_stage16_c_runner",
    C_RUNNER,
)

if spec is None or spec.loader is None:
    raise RuntimeError(
        "FAILED_TO_LOAD_FROZEN_C_RUNNER"
    )

frozen_c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(frozen_c)


MAX_SEARCHES = frozen_c.MAX_SEARCHES
MAX_FILES = frozen_c.MAX_FILES
MAX_LINES = frozen_c.MAX_LINES
MAX_LINES_PER_READ = frozen_c.MAX_LINES_PER_READ


def _record(
    runtime: dict[str, Any],
    tool_name: str,
    result: dict[str, Any],
) -> dict[str, Any]:
    runtime["events"].append({
        "sequence": len(runtime["events"]) + 1,
        "tool": tool_name,
        "result": copy.deepcopy(result),
    })
    return result


def fresh_runtime_state(
    cwe: str,
) -> dict[str, Any]:
    sources = frozen_c.load_c_sources(cwe)

    return {
        "schema_version": "1.0",
        "scope": "TRAIN_VULNERABLE_SOURCE_ONLY",
        "cwe": cwe,
        "benchmarks": {
            bid: {
                "searches": 0,
                "files": set(),
                "lines": 0,
                "hits": {},
            }
            for bid in sorted(sources)
        },
        "events": [],
    }


def snapshot_state(
    runtime: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "scope": runtime["scope"],
        "cwe": runtime["cwe"],
        "benchmarks": {
            bid: {
                "searches": int(u["searches"]),
                "files": sorted(u["files"]),
                "lines": int(u["lines"]),
                "hits": {
                    anchor: sorted(paths)
                    for anchor, paths in sorted(
                        u["hits"].items()
                    )
                },
            }
            for bid, u in sorted(
                runtime["benchmarks"].items()
            )
        },
        "events": copy.deepcopy(
            runtime["events"]
        ),
    }


def validate_snapshot(
    cwe: str,
    snapshot: dict[str, Any],
) -> None:
    if snapshot.get("scope") != "TRAIN_VULNERABLE_SOURCE_ONLY":
        raise RuntimeError(
            "INVALID_C_STATE_SCOPE"
        )

    if snapshot.get("cwe") != cwe:
        raise RuntimeError(
            "C_STATE_CWE_MISMATCH"
        )

    expected = set(
        frozen_c.load_c_sources(cwe)
    )

    actual = set(
        snapshot.get(
            "benchmarks",
            {},
        )
    )

    if actual != expected:
        raise RuntimeError(
            "C_STATE_BENCHMARK_SET_MISMATCH"
        )

    for bid, u in snapshot["benchmarks"].items():
        searches = int(
            u.get("searches", -1)
        )
        lines = int(
            u.get("lines", -1)
        )
        files = list(
            u.get("files", [])
        )

        if not 0 <= searches <= MAX_SEARCHES:
            raise RuntimeError(
                f"C_STATE_SEARCH_BUDGET_INVALID={bid}"
            )

        if not 0 <= len(files) <= MAX_FILES:
            raise RuntimeError(
                f"C_STATE_FILE_BUDGET_INVALID={bid}"
            )

        if not 0 <= lines <= MAX_LINES:
            raise RuntimeError(
                f"C_STATE_LINE_BUDGET_INVALID={bid}"
            )


def restore_state(
    cwe: str,
    snapshot: dict[str, Any],
) -> dict[str, Any]:
    validate_snapshot(
        cwe,
        snapshot,
    )

    return {
        "schema_version": "1.0",
        "scope": "TRAIN_VULNERABLE_SOURCE_ONLY",
        "cwe": cwe,
        "benchmarks": {
            bid: {
                "searches":
                    int(u["searches"]),
                "files":
                    set(u["files"]),
                "lines":
                    int(u["lines"]),
                "hits": {
                    anchor: set(paths)
                    for anchor, paths
                    in u["hits"].items()
                },
            }
            for bid, u
            in snapshot[
                "benchmarks"
            ].items()
        },
        "events": copy.deepcopy(
            snapshot.get(
                "events",
                [],
            )
        ),
    }


def clone_snapshot(
    snapshot: dict[str, Any],
) -> dict[str, Any]:
    return json.loads(
        json.dumps(
            snapshot,
            ensure_ascii=False,
        )
    )


def build_source_tools(
    cwe: str,
    snapshot: dict[str, Any] | None = None,
):
    sources = frozen_c.load_c_sources(cwe)

    (
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        allowed_anchor_text,
    ) = frozen_c.load_ab_evidence(cwe)

    allowed_anchor_lower = (
        allowed_anchor_text.lower()
    )

    runtime = (
        fresh_runtime_state(cwe)
        if snapshot is None
        else restore_state(
            cwe,
            snapshot,
        )
    )

    @tool
    def search_java_anchor(
        benchmark_id: str,
        anchor: str,
    ) -> dict[str, Any]:
        """Search frozen vulnerable Java source using an A/B-visible anchor."""

        if benchmark_id not in sources:
            return _record(
                runtime,
                "search_java_anchor",
                {
                    "ok": False,
                    "error":
                        "Unknown TRAIN benchmark_id",
                },
            )

        anchor = anchor.strip()

        if len(anchor) < 3:
            return _record(
                runtime,
                "search_java_anchor",
                {
                    "ok": False,
                    "error":
                        "Anchor must contain at least 3 characters",
                },
            )

        if anchor.lower() not in allowed_anchor_lower:
            return _record(
                runtime,
                "search_java_anchor",
                {
                    "ok": False,
                    "error": (
                        "ANCHOR_NOT_ALLOWED: anchor does not occur "
                        "in frozen A/B evidence"
                    ),
                },
            )

        u = runtime[
            "benchmarks"
        ][benchmark_id]

        if u["searches"] >= MAX_SEARCHES:
            return _record(
                runtime,
                "search_java_anchor",
                {
                    "ok": False,
                    "error":
                        "ANCHOR_SEARCH_BUDGET_EXHAUSTED",
                    "searches_used":
                        u["searches"],
                    "max_searches":
                        MAX_SEARCHES,
                },
            )

        src = sources[
            benchmark_id
        ]["source"]

        proc = subprocess.run(
            [
                "git",
                "-C",
                str(src),
                "grep",
                "-l",
                "-F",
                "-e",
                anchor,
                "--",
                "*.java",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        if proc.returncode not in (0, 1):
            return _record(
                runtime,
                "search_java_anchor",
                {
                    "ok": False,
                    "error":
                        "git grep failed",
                    "stderr":
                        proc.stderr[-2000:],
                },
            )

        paths = sorted(
            x.strip()
            for x in proc.stdout.splitlines()
            if x.strip().endswith(
                ".java"
            )
        )

        u["searches"] += 1
        u["hits"][anchor] = set(
            paths
        )

        return _record(
            runtime,
            "search_java_anchor",
            {
                "ok": True,
                "scope":
                    "TRAIN_VULNERABLE_SOURCE_ONLY",
                "benchmark_id":
                    benchmark_id,
                "anchor":
                    anchor,
                "matched_java_files":
                    paths,
                "match_count":
                    len(paths),
                "searches_used":
                    u["searches"],
                "searches_remaining":
                    MAX_SEARCHES
                    - u["searches"],
                "instruction": (
                    "Only these directly returned Java files may be "
                    "opened for this anchor."
                ),
            },
        )

    @tool
    def read_java_source_snippet(
        benchmark_id: str,
        relative_path: str,
        anchor: str,
    ) -> dict[str, Any]:
        """Read a bounded snippet from a directly searched vulnerable Java file."""

        if benchmark_id not in sources:
            return _record(
                runtime,
                "read_java_source_snippet",
                {
                    "ok": False,
                    "error":
                        "Unknown TRAIN benchmark_id",
                },
            )

        u = runtime[
            "benchmarks"
        ][benchmark_id]

        if anchor not in u["hits"]:
            return _record(
                runtime,
                "read_java_source_snippet",
                {
                    "ok": False,
                    "error": (
                        "ANCHOR_NOT_SEARCHED: perform an allowed "
                        "search_java_anchor first"
                    ),
                },
            )

        if relative_path not in u["hits"][anchor]:
            return _record(
                runtime,
                "read_java_source_snippet",
                {
                    "ok": False,
                    "error":
                        "FILE_NOT_DIRECT_SEARCH_RESULT_FOR_ANCHOR",
                },
            )

        if not relative_path.endswith(
            ".java"
        ):
            return _record(
                runtime,
                "read_java_source_snippet",
                {
                    "ok": False,
                    "error":
                        "Only Java files are allowed",
                },
            )

        src_root = sources[
            benchmark_id
        ]["source"]

        target = (
            src_root
            / relative_path
        ).resolve()

        try:
            target.relative_to(
                src_root
            )
        except ValueError:
            return _record(
                runtime,
                "read_java_source_snippet",
                {
                    "ok": False,
                    "error":
                        "Path escapes frozen vulnerable source root",
                },
            )

        if not target.exists():
            return _record(
                runtime,
                "read_java_source_snippet",
                {
                    "ok": False,
                    "error":
                        "Source file does not exist",
                },
            )

        is_new = (
            relative_path
            not in u["files"]
        )

        if (
            is_new
            and len(u["files"])
            >= MAX_FILES
        ):
            return _record(
                runtime,
                "read_java_source_snippet",
                {
                    "ok": False,
                    "error":
                        "JAVA_FILE_BUDGET_EXHAUSTED",
                    "files_opened":
                        len(u["files"]),
                    "max_files":
                        MAX_FILES,
                },
            )

        remaining = (
            MAX_LINES
            - u["lines"]
        )

        if remaining <= 0:
            return _record(
                runtime,
                "read_java_source_snippet",
                {
                    "ok": False,
                    "error":
                        "SOURCE_LINE_BUDGET_EXHAUSTED",
                    "lines_exposed":
                        u["lines"],
                    "max_lines":
                        MAX_LINES,
                },
            )

        lines = target.read_text(
            encoding="utf-8",
            errors="replace",
        ).splitlines()

        matches = [
            i
            for i, line
            in enumerate(lines)
            if anchor in line
        ]

        if not matches:
            return _record(
                runtime,
                "read_java_source_snippet",
                {
                    "ok": False,
                    "error":
                        "Anchor no longer found in returned file",
                },
            )

        center = matches[0]

        window = min(
            MAX_LINES_PER_READ,
            remaining,
        )

        start = max(
            0,
            center - window // 2,
        )

        end = min(
            len(lines),
            start + window,
        )

        if end - start < window:
            start = max(
                0,
                end - window,
            )

        exposed = (
            end - start
        )

        u["lines"] += exposed
        u["files"].add(
            relative_path
        )

        numbered = "\n".join(
            f"{i + 1}: {lines[i]}"
            for i in range(
                start,
                end,
            )
        )

        return _record(
            runtime,
            "read_java_source_snippet",
            {
                "ok": True,
                "scope":
                    "TRAIN_VULNERABLE_SOURCE_ONLY",
                "benchmark_id":
                    benchmark_id,
                "relative_path":
                    relative_path,
                "anchor":
                    anchor,
                "start_line":
                    start + 1,
                "end_line":
                    end,
                "source_snippet":
                    numbered,
                "distinct_files_opened":
                    len(u["files"]),
                "files_remaining":
                    MAX_FILES
                    - len(u["files"]),
                "total_source_lines_exposed":
                    u["lines"],
                "source_lines_remaining":
                    MAX_LINES
                    - u["lines"],
                "exploration_depth":
                    1,
                "instruction": (
                    "Do not use newly discovered source text as a new "
                    "repository-wide search anchor."
                ),
            },
        )

    return (
        [
            search_java_anchor,
            read_java_source_snippet,
        ],
        runtime,
    )
