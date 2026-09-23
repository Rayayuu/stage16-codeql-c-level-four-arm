#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.util
import json
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path('/home/ray001/codeql_cwe_expansion/stage16_temporal_generalization_gpt5')
PILOT_ROOT = ROOT / 'train/semantic_modelling/mechanism_first_pilot_v1'
SNAPSHOT = PILOT_ROOT / 'fixed_evidence_snapshot_v1/CWE-639_A_LEVEL_INPUT_v1.json'
SNAPSHOT_MANIFEST = PILOT_ROOT / 'fixed_evidence_snapshot_v1/FIXED_EVIDENCE_SNAPSHOT_MANIFEST_v1.json'
PREREG = PILOT_ROOT / 'MECHANISM_FIRST_EXPERIMENT_PREREGISTRATION_v1.json'
RUBRIC = PILOT_ROOT / 'MECHANISM_FIRST_SEMANTIC_SCORING_RUBRIC_v1.json'
AMENDMENT = PILOT_ROOT / 'MECHANISM_FIRST_MATCHED_CALL_AMENDMENT_v1.json'
ORIGINAL_RUNNER = ROOT / 'train/compilation_improvement/four_arm_runs_v1/implementation/run_four_arm_compilation_experiment_v1_3.py'
PACK_ROOT = ROOT / 'train/compilation_improvement/corrected_replacement_protocol_v2/replacement_qlpack'
QLPACK_FILE = PACK_ROOT / 'qlpack.yml'
PACK_AWARE_EVALUATOR = ROOT / 'train/compilation_improvement/corrected_replacement_protocol_v2/implementation/evaluate_pack_aware_replacement_v2_1.py'
RUNS_ROOT = PACK_ROOT / 'mechanism_first_pilot_runs_v1'

CWE = 'CWE-639'
SUPPORT_ARM = 'V3_LIBRARY_PLUS_AUTO_SKILL'
M0 = 'M0_CONTROL_CWE_FIRST'
M1 = 'M1_MECHANISM_FIRST'
ARMS = (M0, M1)
MAX_REPAIRS = 4

EXPECTED = {
    'snapshot': 'c2b12964eab7af408e3ae46b2f2bfe1a5c5f8b4aafbc1a3e38b0e510c3a760cf',
    'prereg': '4044946dda8ec9f798f32e776a56d5aaf53f405202ef1722ad8f85f397e78cec',
    'rubric': '8cf6219632742f4310e5ddbd9fdcb61944f23bddb4b3f2eeb1e8bfa4e6e9e96d',
    'original_runner': '07cd1058784778a2589d6301fbed4e4f78af4476c61b41b6606045c692388b63',
    'core': 'a2f06b24907fb24abf56f32b49c93f144896253f08713201462c120aaf23f420',
    'base_runner': 'fae6b3a588461587667f320c4f1f20625c778cc0b259bbd1c74b27a73eeb8b01',
}

def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f'MODULE_LOAD_FAILED={path}')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def load_original():
    impl = ORIGINAL_RUNNER.parent
    if str(impl) not in sys.path:
        sys.path.insert(0, str(impl))
    return load_module('_mechanism_first_original_v13', ORIGINAL_RUNNER)

def arm_run_root(arm: str) -> Path:
    if arm not in ARMS:
        raise ValueError(f'INVALID_TREATMENT_ARM={arm}')
    return RUNS_ROOT / arm

def configure_original_namespace(orig, arm: str) -> Path:
    run_root = arm_run_root(arm).resolve()
    run_root.relative_to(PACK_ROOT.resolve())
    orig.RUN_ROOT = run_root
    orig.EVAL_ROOT = run_root / 'query_evaluations'
    orig.EVALUATOR = PACK_AWARE_EVALUATOR
    orig.core.RUN_ROOT = run_root
    if hasattr(orig.core, 'EVAL_ROOT'):
        orig.core.EVAL_ROOT = orig.EVAL_ROOT
    return run_root

def fixed_user_input(orig) -> str:
    task = orig.base.TASK_PROMPT.read_text(encoding='utf-8')
    evidence = SNAPSHOT.read_text(encoding='utf-8')
    return (
        '===== FROZEN CWE-LEVEL SYNTHESIS TASK =====\n' + task + '\n\n'
        '===== FROZEN A-LEVEL HISTORICAL TRAIN EVIDENCE =====\n' + evidence + '\n\n'
        '===== EXECUTION INSTRUCTION =====\n'
        'Use only this fixed TRAIN evidence snapshot. Produce one CWE-level Java CodeQL query '
        'for all seven TRAIN cases. Do not access TEST.'
    )

def write_once(path: Path, text: str) -> None:
    if path.exists():
        raise FileExistsError(f'REFUSE_OVERWRITE={path}')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.strip() + '\n', encoding='utf-8')

async def generate_initial(arm: str) -> None:
    from langchain_core.tools import tool
    from react_agent.utils import load_chat_model

    orig = load_original()
    run_root = configure_original_namespace(orig, arm)
    master = orig.core.shared_initial_master_path(CWE)
    if master.exists():
        raise RuntimeError(f'INITIAL_ALREADY_EXISTS={master}')
    staging = run_root / 'shared_initial_staging' / CWE / 'iter0_candidate.ql'
    if staging.exists():
        raise RuntimeError(f'STALE_STAGING={staging}')

    meta_dir = PILOT_ROOT / 'arm_outputs_v1' / arm / CWE
    plan_path = meta_dir / 'planning_stage.txt'
    generation_path = meta_dir / 'initial_generation.json'
    if generation_path.exists() or plan_path.exists():
        raise RuntimeError(f'ARM_GENERATION_ALREADY_STARTED={meta_dir}')

    @tool
    def write_planning_stage(plan_text: str) -> dict[str, Any]:
        '''Freeze the treatment arm planning output before CodeQL synthesis.'''
        write_once(plan_path, plan_text)
        return {'ok': True, 'plan_path': str(plan_path), 'plan_sha256': sha256_file(plan_path)}

    @tool
    def write_initial_query(query_text: str) -> dict[str, Any]:
        '''Write exactly one fresh initial Java CodeQL query.'''
        cleaned = query_text.strip()
        if cleaned.startswith('```'):
            lines = cleaned.splitlines()
            if lines and lines[0].startswith('```'):
                lines = lines[1:]
            if lines and lines[-1].strip() == '```':
                lines = lines[:-1]
            cleaned = '\n'.join(lines).strip()
        write_once(staging, cleaned)
        return {'ok': True, 'query_path': str(staging), 'query_sha256': sha256_file(staging)}

    base_input = fixed_user_input(orig)
    system_prompt = orig.base.SYSTEM_PROMPT
    token_records = []
    model_calls = 0
    start = time.perf_counter()

    if arm == M0:
        plan_instruction = (
            '\n\n===== M0 MATCHED CWE-FIRST PLANNING STAGE =====\n'
            'Do NOT generate CodeQL in this stage. Follow the existing CWE-first reasoning style: infer ONE general '
            'Java security/CodeQL pattern for CWE-639 from the supplied A-level TRAIN evidence. Do not perform a '
            'mandatory decomposition into distinct vulnerability mechanism families and do not use the Sept18 human '
            'taxonomy. State the generic CWE-level pattern, likely sources/sinks/security checks at a high level, and '
            'a reusable implementation strategy without CVE-specific hard-coding. Call write_planning_stage exactly once. '
            'Do not access patch/source B/C evidence, repository source, prior CWE-639 queries/results/repair trajectories, '
            'Sept18 human semantic analysis, or TEST.'
        )
    else:
        plan_instruction = (
            '\n\n===== M1 MECHANISM-FIRST SEMANTIC PLANNING STAGE =====\n'
            'Do NOT generate CodeQL in this stage. Infer distinct vulnerability mechanism families from the supplied '
            'A-level TRAIN evidence. For each inferred family identify: subject/principal; target resource or '
            'security-sensitive object; security relation; validation/authorization boundary; relevant propagation/context; '
            'and vulnerable-versus-fixed distinction to the extent supported by the A-level advisory evidence. If a detail '
            'is unavailable, mark it unknown rather than inventing it. Explicitly identify which inferred families cannot be '
            'represented by a simple user-controlled-ID -> ID-like resource-operation taint template. Then propose ONE '
            'CWE-level semantic abstraction that can represent the inferred TRAIN families without CVE IDs, repository paths, '
            'commit hashes, or per-CVE hard-coding. Call write_planning_stage exactly once. Do not access patch/source B/C '
            'evidence, repository source, prior CWE-639 queries/results/repair trajectories, Sept18 human semantic analysis, or TEST.'
        )

    planning_model = load_chat_model(orig.MODEL).bind_tools([write_planning_stage])
    planning_response = await planning_model.ainvoke([
        {'role': 'system', 'content': system_prompt},
        {'role': 'user', 'content': base_input + plan_instruction},
    ])
    model_calls += 1
    token_records.append(orig.parse_model_usage(planning_response))
    calls = planning_response.tool_calls or []
    if len(calls) != 1 or calls[0].get('name') != 'write_planning_stage':
        raise RuntimeError('EXPECTED_ONE_PLANNING_TOOL_CALL=' + repr(calls))
    plan_result = write_planning_stage.invoke(calls[0].get('args', {}))
    if not plan_result.get('ok'):
        raise RuntimeError('PLANNING_WRITE_FAILED=' + repr(plan_result))

    frozen_plan = plan_path.read_text(encoding='utf-8')
    if arm == M0:
        synthesis_instruction = (
            '\n\n===== M0 CWE-FIRST CODEQL SYNTHESIS STAGE =====\n'
            'Use the frozen CWE-first planning output below to generate exactly ONE complete CWE-level Java CodeQL query. '
            'Do not add a new mandatory mechanism-family decomposition. Multiple standard CodeQL constructs are allowed, '
            'but preserve the generic CWE-first reasoning approach. Do not hard-code CVE IDs or case-specific constants.\n\n'
        )
    else:
        synthesis_instruction = (
            '\n\n===== M1 MECHANISM-FIRST CODEQL SYNTHESIS STAGE =====\n'
            'Use the frozen mechanism-first planning output below to generate exactly ONE complete CWE-level Java CodeQL query. '
            'Multiple semantic branches are permitted when needed to represent heterogeneous mechanism families. Do not collapse '
            'the plan back to a generic ID-to-resource-operation pattern when the plan identified other decisive relations, '
            'validations, protocol conditions, credentials, or security objects. Do not hard-code CVE IDs or case-specific constants.\n\n'
        )
    synthesis_instruction += (
        '----- FROZEN PLANNING OUTPUT -----\n' + frozen_plan + '\n----- END FROZEN PLANNING OUTPUT -----\n\n'
        'Call write_initial_query exactly once. Do not evaluate or repair it. Do not access patch/source B/C evidence, '
        'repository source, prior CWE-639 queries/results/repair trajectories, Sept18 human semantic analysis, or TEST.'
    )

    query_model = load_chat_model(orig.MODEL).bind_tools([write_initial_query])
    query_response = await query_model.ainvoke([
        {'role': 'system', 'content': system_prompt},
        {'role': 'user', 'content': base_input + synthesis_instruction},
    ])
    model_calls += 1
    token_records.append(orig.parse_model_usage(query_response))
    qcalls = query_response.tool_calls or []
    if len(qcalls) != 1 or qcalls[0].get('name') != 'write_initial_query':
        raise RuntimeError('EXPECTED_ONE_QUERY_TOOL_CALL=' + repr(qcalls))
    query_result = write_initial_query.invoke(qcalls[0].get('args', {}))
    if not query_result.get('ok'):
        raise RuntimeError('INITIAL_QUERY_WRITE_FAILED=' + repr(query_result))

    manifest = orig.core.freeze_and_fork_initial_query(CWE, staging)
    staging.unlink()
    try:
        staging.parent.rmdir()
    except OSError:
        pass

    elapsed = round(time.perf_counter() - start, 6)
    usage = orig.core.aggregate_token_records(token_records)
    meta_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        'schema_version': '1.0', 'scope': 'TRAIN_ONLY', 'pilot_cwe': CWE,
        'treatment_arm': arm, 'support_stack_arm': SUPPORT_ARM,
        'model': orig.MODEL, 'evidence_snapshot': str(SNAPSHOT),
        'evidence_snapshot_sha256': sha256_file(SNAPSHOT),
        'planning_stage_path': str(plan_path), 'planning_stage_sha256': sha256_file(plan_path),
        'shared_initial_sha256': manifest['shared_initial_sha256'],
        'model_call_count': model_calls, 'token_usage': usage, 'wall_clock_sec': elapsed,
        'model_execution': True, 'codeql_execution': False, 'test_access': 'FORBIDDEN'
    }
    generation_path.write_text(json.dumps(payload, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(payload, indent=2))

def evaluate_initial(arm: str) -> None:
    orig = load_original()
    configure_original_namespace(orig, arm)
    orig.evaluate_shared_initial(CWE)

async def run_repairs(arm: str) -> None:
    orig = load_original()
    configure_original_namespace(orig, arm)
    await orig.run_arm(CWE, SUPPORT_ARM)

def self_check() -> dict[str, Any]:
    checks: dict[str, bool] = {}
    for name, path in [('snapshot', SNAPSHOT), ('snapshot_manifest', SNAPSHOT_MANIFEST), ('prereg', PREREG), ('rubric', RUBRIC), ('amendment', AMENDMENT), ('original_runner', ORIGINAL_RUNNER), ('qlpack', QLPACK_FILE), ('pack_evaluator', PACK_AWARE_EVALUATOR)]:
        checks[name + '_exists'] = path.is_file()
    if SNAPSHOT.is_file(): checks['snapshot_sha_frozen'] = sha256_file(SNAPSHOT) == EXPECTED['snapshot']
    if PREREG.is_file(): checks['prereg_sha_frozen'] = sha256_file(PREREG) == EXPECTED['prereg']
    if RUBRIC.is_file(): checks['rubric_sha_frozen'] = sha256_file(RUBRIC) == EXPECTED['rubric']
    if ORIGINAL_RUNNER.is_file(): checks['original_runner_sha_frozen'] = sha256_file(ORIGINAL_RUNNER) == EXPECTED['original_runner']

    model = None; base_runner = None; core_path = None
    try:
        orig = load_original(); model = orig.MODEL; base_runner = orig.BASE_RUNNER_PATH; core_path = orig.CORE_PATH
        checks['original_import_ok'] = True
        checks['support_arm_registered'] = SUPPORT_ARM in orig.ARMS
        checks['max_repairs_4'] = orig.MAX_REPAIRS == MAX_REPAIRS
        checks['core_sha_frozen'] = sha256_file(core_path) == EXPECTED['core']
        checks['base_runner_sha_frozen'] = sha256_file(base_runner) == EXPECTED['base_runner']
        checks['target_cwe_registered'] = CWE in orig.TARGET_CWES
    except Exception:
        checks['original_import_ok'] = False

    snap = json.loads(SNAPSHOT.read_text(encoding='utf-8')) if SNAPSHOT.is_file() else {}
    sm = json.loads(SNAPSHOT_MANIFEST.read_text(encoding='utf-8')) if SNAPSHOT_MANIFEST.is_file() else {}
    amendment = json.loads(AMENDMENT.read_text(encoding='utf-8')) if AMENDMENT.is_file() else {}
    checks['snapshot_cwe_639'] = snap.get('cwe') == CWE
    checks['snapshot_train_count_7'] = snap.get('train_case_count') == 7
    checks['snapshot_evidence_A'] = snap.get('evidence_level') == 'A'
    checks['snapshot_identical_to_canonical'] = sm.get('identical_bytes') is True
    checks['m0_m1_same_snapshot'] = sm.get('shared_by_arms') == [M0, M1]
    checks['matched_planning_calls_preregistered'] = amendment.get('matched_pre_generation_model_calls') is True
    try:
        RUNS_ROOT.resolve().relative_to(PACK_ROOT.resolve()); checks['runs_root_inside_qlpack'] = True
    except Exception:
        checks['runs_root_inside_qlpack'] = False
    checks['test_not_in_runs_root'] = '/test/' not in str(RUNS_ROOT).lower()
    checks['m0_not_started'] = not arm_run_root(M0).exists()
    checks['m1_not_started'] = not arm_run_root(M1).exists()
    checks['m0_metadata_not_started'] = not (PILOT_ROOT / 'arm_outputs_v1' / M0).exists()
    checks['m1_metadata_not_started'] = not (PILOT_ROOT / 'arm_outputs_v1' / M1).exists()

    return {
        'status': 'PASS' if all(checks.values()) else 'FAIL', 'checks': checks,
        'pilot_cwe': CWE, 'train_case_count': 7, 'treatment_arms': list(ARMS),
        'support_stack_arm': SUPPORT_ARM, 'model': model,
        'base_runner': str(base_runner) if base_runner else None, 'core': str(core_path) if core_path else None,
        'run_root': str(RUNS_ROOT), 'evidence_snapshot': str(SNAPSHOT),
        'evidence_snapshot_sha256': sha256_file(SNAPSHOT) if SNAPSHOT.is_file() else None,
        'matched_call_structure': 'Both M0 and M1 use one planning call followed by one query-synthesis call.',
        'm0_treatment': 'Generic CWE-first planning; no mandatory mechanism-family decomposition.',
        'm1_treatment': 'Explicit mechanism-family decomposition before query synthesis.',
        'same_evidence': True, 'same_model_call_count_initial_stage': True,
        'same_codeql_library_skill_repair_stack': True,
        'human_sept18_generation_input': False, 'prior_target_query_generation_input': False,
        'model_execution': False, 'codeql_execution': False, 'test_access': 'FORBIDDEN',
        'next_stage': 'FREEZE_HARNESS_SHA256_THEN_RUN_M0_INITIAL_GENERATION_ONLY'
    }

def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument('--self-check', action='store_true')
    p.add_argument('--stage', choices=['generate', 'evaluate-initial', 'repair'])
    p.add_argument('--arm', choices=ARMS)
    args = p.parse_args()
    if args.self_check:
        print('===== MECHANISM-FIRST PILOT HARNESS DRY SELF-CHECK =====')
        print('MODE=DRY_SELF_CHECK'); print('TRAIN_ONLY=YES'); print('TEST_ACCESS=FORBIDDEN')
        print('MODEL_EXECUTION=NO'); print('CODEQL_EXECUTION=NO'); print('QUERY_MODIFICATION=NO')
        print('SCIENTIFIC_RERUN=NO'); print('FROZEN_RESULTS_MODIFIED=NO')
        result = self_check(); print(json.dumps(result, indent=2))
        print('HARNESS_SELF_CHECK=' + result['status']); print('TEST_ACCESSED=NO')
        raise SystemExit(0 if result['status'] == 'PASS' else 2)
    if not args.stage or not args.arm:
        raise SystemExit('--stage and --arm are required unless --self-check is used')
    if args.stage == 'generate': asyncio.run(generate_initial(args.arm))
    elif args.stage == 'evaluate-initial': evaluate_initial(args.arm)
    elif args.stage == 'repair': asyncio.run(run_repairs(args.arm))

if __name__ == '__main__':
    main()
