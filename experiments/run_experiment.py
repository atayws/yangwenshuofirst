# 中文注释。
"""
运行基线与自适应方案对比实验的脚本。
"""

import argparse
import os
import sys
import json
import time
from pathlib import Path

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from python.rl_agent.ppo_agent import PPOAgent
from python.simulation.covert_env import CovertMultiPathEnv
from python.simulation.scenario_loader import ScenarioLibrary
from python.monitoring.metrics_collector import MetricsCollector
from python.monitoring.visualization import ExperimentVisualizer
from python.utils.config import load_config


def parse_args():
    parser = argparse.ArgumentParser(description="Run covert transmission experiment")
    parser.add_argument("--config", type=str, default="experiments/configs/default.yaml")
    parser.add_argument("--scenario", type=str, default="static_good")
    parser.add_argument("--model", type=str, default="ppo_best.pth")
    parser.add_argument("--episodes", type=int, default=10)
    parser.add_argument("--output-dir", type=str, default="experiments/results/")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--deterministic", action="store_true", default=True)
    return parser.parse_args()


def run_baseline_static(scenario_name: str, config: dict, args) -> dict:
    """
    run_baseline_static 函数。
    """
    results = {}
    num_paths = config.get("network.num_links", 3)
    max_steps = config.get("experiment.steps_per_episode", 500)

    for strat_id in range(5):
        print(f"\n  Baseline: Strategy {strat_id} on all paths")

        env = CovertMultiPathEnv(
            num_links=num_paths,
            scenario=scenario_name,
            max_steps=max_steps,
        )

        collector = MetricsCollector()
        global_step = 0

        for ep in range(args.episodes):
            obs, _ = env.reset(seed=args.seed + ep)

            for _ in range(max_steps):
                action = np.array([strat_id] * num_paths, dtype=np.int32)
                next_obs, reward, terminated, truncated, info = env.step(action)
                collector.record_step(global_step, info)
                global_step += 1
                obs = next_obs
                if terminated or truncated:
                    break

            collector.end_episode(ep)

        env.close()

        episode_stats = collector._compute_overall_metrics()
        episode_stats["strategy_id"] = strat_id
        results[f"strategy_{strat_id}"] = episode_stats

    return results


def run_rl_adaptive(model_path: str, scenario_name: str, config: dict, args) -> dict:
    """
    run_rl_adaptive 函数。
    """
    print(f"\n  RL-Adaptive system (model: {model_path})")

    num_paths = config.get("network.num_links", 3)
    max_steps = config.get("experiment.steps_per_episode", 500)

    # 中文注释。
    agent = PPOAgent(
        num_paths=num_paths,
        state_dim=num_paths * 4,
        config=config.get("rl", {}),
    )

    full_model_path = os.path.join(args.output_dir, "models", model_path)
    if os.path.exists(full_model_path):
        agent.load(full_model_path)
        print(f"  Loaded model from {full_model_path}")
    else:
        print(f"  Warning: Model not found at {full_model_path}. Using untrained agent.")

    # 中文注释。
    env = CovertMultiPathEnv(
        num_links=num_paths,
        scenario=scenario_name,
        max_steps=max_steps,
    )

    collector = MetricsCollector()
    viz = ExperimentVisualizer(num_paths=num_paths)
    global_step = 0

    for ep in range(args.episodes):
        obs, _ = env.reset(seed=args.seed + ep)

        for _ in range(max_steps):
            action, _, _ = agent.select_action(obs, deterministic=args.deterministic)
            next_obs, reward, terminated, truncated, info = env.step(action)
            collector.record_step(global_step, info)
            viz.update(global_step, info)
            global_step += 1
            obs = next_obs
            if terminated or truncated:
                break

        collector.end_episode(ep)

    env.close()

    return {
        "adaptive": collector._compute_overall_metrics(),
        "collector": collector,
        "viz": viz,
    }


def main():
    args = parse_args()
    config = load_config(args.config)

    os.makedirs(os.path.join(args.output_dir, "summary"), exist_ok=True)
    os.makedirs(os.path.join(args.output_dir, "plots"), exist_ok=True)

    print(f"{'='*60}")
    print(f"  Multi-Path Covert Transmission Experiment")
    print(f"  Scenario: {args.scenario}")
    print(f"  Model: {args.model}")
    print(f"{'='*60}")

    # 中文注释。
    print("\n[1/2] Running baseline strategies...")
    baseline_results = run_baseline_static(args.scenario, config, args)

    # 中文注释。
    print("\n[2/2] Running RL-adaptive system...")
    rl_results = run_rl_adaptive(args.model, args.scenario, config, args)

    # 中文注释。
    print(f"\n{'='*60}")
    print(f"  Results Comparison")
    print(f"{'='*60}")

    comparison = {}
    for key, result in baseline_results.items():
        comparison[key] = {
            "mean_reward": result.get("mean_reward_per_episode", 0),
            "mean_throughput": result.get("mean_throughput_bps", 0),
            "detection_rate": result.get("mean_detection_rate", 0),
        }

    if "collector" in rl_results:
        rl_overall = rl_results["adaptive"]
        comparison["rl_adaptive"] = {
            "mean_reward": rl_overall.get("mean_reward_per_episode", 0),
            "mean_throughput": rl_overall.get("mean_throughput_bps", 0),
            "detection_rate": rl_overall.get("mean_detection_rate", 0),
        }

    # 中文注释。
    print(f"\n{'Method':<25} {'Reward':>8} {'Throughput':>12} {'Detect Rate':>12}")
    print("-" * 60)
    for method, metrics in comparison.items():
        print(f"  {method:<23} {metrics['mean_reward']:>+8.3f} "
              f"{metrics['mean_throughput']:>9.1f} bps "
              f"{metrics['detection_rate']:>9.1%}")

    # 中文注释。
    full_results = {
        "scenario": args.scenario,
        "baselines": baseline_results,
        "rl_adaptive": rl_results.get("adaptive", {}),
        "comparison": comparison,
    }

    results_path = os.path.join(args.output_dir, "summary", f"comparison_{args.scenario}.json")
    with open(results_path, "w", encoding="utf-8") as f:
        json.dump(full_results, f, indent=2, ensure_ascii=False)

    print(f"\nResults saved to {results_path}")

    # 中文注释。
    if "viz" in rl_results:
        rl_results["viz"].generate_all_plots(
            os.path.join(args.output_dir, "plots")
        )
        print(f"Plots saved to {os.path.join(args.output_dir, 'plots')}")


if __name__ == "__main__":
    main()
