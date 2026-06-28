#!/usr/bin/env python3
"""
规则切换策略 live 演示。

该脚本用于中期阶段验证“INT -> 规则选择 -> 策略执行”的闭环：
1. 先按场景设置三条链路的 delay/loss；
2. 运行一次 live 闭环，让反向 UDP iperf 触发 INT；
3. 根据 INT 输出的 path_states 生成策略计划；
4. 再用该计划运行一次 live 闭环，验证业务流、INT 和隐蔽数据是否同时成功。

后续接入 PPO 时，只需要把 RuleBasedPolicySelector 替换为 PPO 输出同格式计划。
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from experiments.verify_manual_policy_session import PolicyEntry, write_policy_plan
from python.control_plane.rule_policy_selector import RuleBasedPolicySelector


RESULTS_DIR = PROJECT_ROOT / "experiments" / "results" / "rule_switch_demo"
MANUAL_RESULTS_DIR = PROJECT_ROOT / "experiments" / "results" / "manual_policy_live"

SCENARIOS = {
    "clean": [
        "0:5:0",
        "1:15:0",
        "2:30:0",
    ],
    "lossy_path1": [
        "0:5:0",
        "1:20:12",
        "2:35:2",
    ],
    "delay_loss_mixed": [
        "0:10:0",
        "1:45:5",
        "2:80:15",
    ],
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="规则切换策略 live 演示")
    parser.add_argument("--timeout", type=int, default=260)
    parser.add_argument("--chunk-size", type=int, default=4)
    parser.add_argument("--session-id", type=int, default=80)
    parser.add_argument(
        "--scenario",
        action="append",
        choices=sorted(SCENARIOS),
        help="只运行指定场景；可重复。不指定则运行全部场景。",
    )
    parser.add_argument("--clean-results", action="store_true")
    return parser.parse_args()


def run_manual_live(
    args: argparse.Namespace,
    scenario_name: str,
    links: list[str],
    plan_file: Path | None,
    session_id: int,
    stage: str,
) -> dict:
    """运行一次 live 闭环并读取 summary。"""

    cmd = [
        "sudo",
        "python3",
        "experiments/run_manual_policy_live.py",
        "--timeout",
        str(args.timeout),
        "--chunk-size",
        str(args.chunk_size),
        "--session-id",
        str(session_id),
        "--clean-results",
    ]
    for link in links:
        cmd.extend(["--link", link])
    if plan_file is not None:
        cmd.extend(["--plan-file", str(plan_file)])

    print(f"[rule-demo] 场景 {scenario_name}: 运行 {stage} live")
    proc = subprocess.run(cmd, cwd=str(PROJECT_ROOT), check=False)
    summary = json.loads((MANUAL_RESULTS_DIR / "summary.json").read_text(encoding="utf-8"))
    if stage != "probe" and proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, cmd)

    scenario_dir = RESULTS_DIR / scenario_name
    scenario_dir.mkdir(parents=True, exist_ok=True)
    suffix = stage
    (scenario_dir / f"{suffix}_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return summary


def ensure_six_strategy_plan(path: Path) -> None:
    """写出一份覆盖策略0-5的探测计划，用于第一轮采集 INT。"""

    plan = [
        PolicyEntry("path0_timing_s0", 0, (0,), 1),
        PolicyEntry("path1_timing_s1", 1, (1,), 1),
        PolicyEntry("path2_ipid_s2", 2, (2,), 1),
        PolicyEntry("path0_length_s3", 3, (0,), 1),
        PolicyEntry("path01_fountain_s4", 4, (0, 1), 1),
        PolicyEntry("path012_sequence_s5", 5, (0, 1, 2), 1),
    ]
    write_policy_plan(path, plan, extra={"source": "run_rule_switch_demo_probe"})


def main() -> int:
    args = parse_args()
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    selected = args.scenario or list(SCENARIOS.keys())
    selector = RuleBasedPolicySelector()
    all_results = []
    probe_plan = RESULTS_DIR / "six_strategy_probe_plan.json"
    ensure_six_strategy_plan(probe_plan)

    for index, scenario_name in enumerate(selected):
        links = SCENARIOS[scenario_name]
        scenario_dir = RESULTS_DIR / scenario_name
        scenario_dir.mkdir(parents=True, exist_ok=True)

        probe_summary = run_manual_live(
            args,
            scenario_name,
            links,
            probe_plan,
            args.session_id + index * 10,
            "probe",
        )
        path_states = {
            int(path_id): state
            for path_id, state in probe_summary.get("int_path_states", {}).items()
        }
        plan = selector.select(path_states)
        plan_file = scenario_dir / "rule_plan.json"
        write_policy_plan(
            plan_file,
            plan,
            extra={
                "source": "RuleBasedPolicySelector",
                "scenario": scenario_name,
                "links": links,
                "input_path_states": path_states,
            },
        )

        rule_summary = run_manual_live(
            args,
            scenario_name,
            links,
            plan_file,
            args.session_id + index * 10 + 1,
            "rule",
        )
        scenario_result = {
            "scenario": scenario_name,
            "links": links,
            "success": bool(rule_summary.get("success")),
            "hidden_match": bool(rule_summary.get("hidden_match")),
            "iperf_ok": bool(rule_summary.get("iperf_ok")),
            "int_success": bool(rule_summary.get("int_success")),
            "probe_int_path_states": path_states,
            "rule_plan": [entry.to_dict() for entry in plan],
            "rule_manifest": rule_summary.get("manifest", []),
            "rule_int_path_states": rule_summary.get("int_path_states", {}),
        }
        (scenario_dir / "scenario_result.json").write_text(
            json.dumps(scenario_result, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        all_results.append(scenario_result)

    final = {
        "success": all(item["success"] for item in all_results),
        "scenario_count": len(all_results),
        "results": all_results,
    }
    (RESULTS_DIR / "summary.json").write_text(
        json.dumps(final, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(json.dumps(final, ensure_ascii=False, indent=2))
    return 0 if final["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
