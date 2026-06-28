#!/usr/bin/env python3
"""
阶段二规则控制闭环验证。

流程：
1. 先运行一次基础 live 闭环，用 h2->h1 UDP 业务流触发 INT，并得到三条链路状态。
2. 根据 INT 状态调用 RuleBasedPolicySelector 生成策略计划 JSON。
3. 再运行一次 live 闭环，发送端和接收端都使用该计划文件。

该脚本是 PPO 接入前的可运行基线。后续 PPO 只需要替换规则选择器，输出同样格式的计划。
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

from experiments.verify_manual_policy_session import write_policy_plan
from python.control_plane.rule_policy_selector import RuleBasedPolicySelector


RESULTS_DIR = PROJECT_ROOT / "experiments" / "results" / "stage2_rule_live"
BASE_RESULTS_DIR = PROJECT_ROOT / "experiments" / "results" / "manual_policy_live"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="阶段二规则控制 live 闭环验证")
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--chunk-size", type=int, default=7)
    parser.add_argument("--session-id", type=int, default=8)
    parser.add_argument("--clean-results", action="store_true")
    return parser.parse_args()


def run_manual_live(args: argparse.Namespace, plan_file: Path | None = None) -> dict:
    """运行一次 manual-policy live 脚本并读取结果。"""
    cmd = [
        "sudo",
        "python3",
        "experiments/run_manual_policy_live.py",
        "--timeout",
        str(args.timeout),
        "--chunk-size",
        str(args.chunk_size),
        "--session-id",
        str(args.session_id),
        "--clean-results",
    ]
    if plan_file is not None:
        cmd.extend(["--plan-file", str(plan_file)])
    subprocess.run(cmd, cwd=str(PROJECT_ROOT), check=True)
    return json.loads((BASE_RESULTS_DIR / "summary.json").read_text(encoding="utf-8"))


def main() -> int:
    args = parse_args()
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    base_summary = run_manual_live(args)
    path_states = {
        int(path_id): state
        for path_id, state in base_summary.get("int_path_states", {}).items()
    }

    selector = RuleBasedPolicySelector()
    plan = selector.select(path_states)
    plan_file = RESULTS_DIR / "rule_plan.json"
    write_policy_plan(
        plan_file,
        plan,
        extra={
            "source": "RuleBasedPolicySelector",
            "input_path_states": path_states,
        },
    )

    rule_summary = run_manual_live(args, plan_file)
    final_summary = {
        "success": bool(rule_summary.get("success")),
        "base_success": bool(base_summary.get("success")),
        "rule_success": bool(rule_summary.get("success")),
        "rule_plan": [entry.to_dict() for entry in plan],
        "base_int_path_states": path_states,
        "rule_hidden_match": rule_summary.get("hidden_match"),
        "rule_iperf_ok": rule_summary.get("iperf_ok"),
        "rule_int_success": rule_summary.get("int_success"),
        "rule_manifest": rule_summary.get("manifest", []),
        "rule_summary_path": str(BASE_RESULTS_DIR / "summary.json"),
        "plan_file": str(plan_file),
    }
    (RESULTS_DIR / "summary.json").write_text(
        json.dumps(final_summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(json.dumps(final_summary, ensure_ascii=False, indent=2))
    return 0 if final_summary["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
