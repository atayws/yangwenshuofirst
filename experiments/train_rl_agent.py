# 中文注释。
"""
训练 PPO 隐蔽策略选择智能体的脚本。
"""

import argparse
import os
import sys
import json
import time
from pathlib import Path

import numpy as np
import torch

# 中文注释。
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from python.rl_agent.ppo_agent import PPOAgent
from python.simulation.covert_env import CovertMultiPathEnv
from python.simulation.scenario_loader import ScenarioLibrary
from python.monitoring.metrics_collector import MetricsCollector
from python.monitoring.visualization import ExperimentVisualizer
from python.utils.config import load_config


def parse_args():
    parser = argparse.ArgumentParser(
        description="Train PPO agent for multi-path covert strategy selection"
    )
    parser.add_argument(
        "--config", type=str, default="experiments/configs/default.yaml",
        help="Path to YAML configuration file"
    )
    parser.add_argument(
        "--episodes", type=int, default=500,
        help="Number of training episodes"
    )
    parser.add_argument(
        "--scenario", type=str, default="static_good",
        choices=ScenarioLibrary.list_scenarios(),
        help="Training scenario"
    )
    parser.add_argument(
        "--curriculum", action="store_true", default=True,
        help="Use curriculum learning (progressively harder scenarios)"
    )
    parser.add_argument(
        "--no-curriculum", dest="curriculum", action="store_false",
        help="Train only on --scenario"
    )
    parser.add_argument(
        "--resume", type=str, default=None,
        help="Resume training from a saved model checkpoint"
    )
    parser.add_argument(
        "--output-dir", type=str, default="experiments/results/",
        help="Output directory for results"
    )
    parser.add_argument(
        "--seed", type=int, default=42,
        help="Random seed"
    )
    parser.add_argument(
        "--render", action="store_true", default=False,
        help="Render environment during training"
    )
    return parser.parse_args()


def set_seed(seed: int):
    """设置随机种子以便复现实验。"""
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed(seed)


def train_curriculum(
    agent: PPOAgent,
    output_dir: str,
    config: dict,
    args,
):
    """
    train_curriculum 函数。
    """
    stages = [
        ("static_good",         max(50, args.episodes // 4)),
        ("dynamic_fluctuation", max(50, args.episodes // 4)),
        ("link_failure",        max(50, args.episodes // 4)),
        ("high_mobility",       max(50, args.episodes // 4)),
    ]

    collector = MetricsCollector()
    num_links = config.get("network.num_links", 3)
    viz = ExperimentVisualizer(num_paths=num_links)
    best_mean_reward = float("-inf")
    total_steps = 0
    episode_offset = 0

    for stage_name, num_episodes in stages:
        print(f"\n{'='*60}")
        print(f"  STAGE: {stage_name} ({num_episodes} episodes)")
        print(f"{'='*60}")

        env = CovertMultiPathEnv(
            num_links=num_links,
            scenario=stage_name,
            max_steps=config.get("experiment.steps_per_episode", 500),
            message_size_bytes=config.get("experiment.message_size_bytes", 16),
            target_throughput_bps=config.get("experiment.target_throughput_bps", 100),
        )

        for ep in range(num_episodes):
            obs, _ = env.reset()
            episode_reward = 0.0
            episode_steps = 0

            done = False
            while not done:
                # 中文注释。
                action, log_prob, value = agent.select_action(obs)

                # 中文注释。
                next_obs, reward, terminated, truncated, info = env.step(action)
                done = terminated or truncated

                # 中文注释。
                agent.store_experience(obs, action, reward, done)

                # 中文注释。
                collector.record_step(total_steps, info)
                viz.update(total_steps, info)

                obs = next_obs
                episode_reward += reward
                episode_steps += 1
                total_steps += 1

                if args.render and total_steps % 100 == 0:
                    env.render()

            # 中文注释。
            collector.end_episode(episode_offset + ep)
            mean_reward = episode_reward / max(episode_steps, 1)

            # 中文注释。
            if mean_reward > best_mean_reward:
                best_mean_reward = mean_reward
                agent.save(os.path.join(output_dir, "models", "ppo_best.pth"))
                print(f"  [New best] Episode {episode_offset + ep}: "
                      f"mean_reward={mean_reward:.3f}")

            # 中文注释。
            if agent.should_update():
                update_metrics = agent.update()
                if (episode_offset + ep) % 50 == 0:
                    print(f"  [Update] Episode {episode_offset + ep}: "
                          f"policy_loss={update_metrics.get('policy_loss', 0):.4f}, "
                          f"value_loss={update_metrics.get('value_loss', 0):.4f}")

            # 中文注释。
            if (episode_offset + ep) % config.get("experiment.save_interval_episodes", 50) == 0:
                agent.save(os.path.join(output_dir, "models", f"ppo_ep{episode_offset + ep}.pth"))
                collector.export_summary(os.path.join(output_dir, "summary", "training_progress.json"))

            if (episode_offset + ep) % 50 == 0:
                stats = env.get_episode_stats()
                print(f"  Episode {episode_offset + ep:4d} | "
                      f"Reward: {stats.get('mean_reward', 0):+.3f} | "
                      f"Throughput: {stats.get('mean_throughput', 0):.1f} bps | "
                      f"Detect: {stats.get('detection_rate', 0):.1%} | "
                      f"Strategies: {stats.get('strategy_distribution', {})}")

        episode_offset += num_episodes
        env.close()

    # 中文注释。
    agent.save(os.path.join(output_dir, "models", "ppo_final.pth"))
    collector.export_summary(os.path.join(output_dir, "summary", "training_final.json"))

    print(f"\nTraining complete! Best mean reward: {best_mean_reward:.3f}")
    return collector, viz


def train_single_scenario(agent, env, collector, viz, args, config):
    """train_single_scenario 函数。"""
    best_mean_reward = float("-inf")
    output_dir = args.output_dir
    total_steps = 0

    for ep in range(args.episodes):
        obs, _ = env.reset()
        episode_reward = 0.0
        episode_steps = 0

        done = False
        while not done:
            action, log_prob, value = agent.select_action(obs)
            next_obs, reward, terminated, truncated, info = env.step(action)
            done = terminated or truncated

            agent.store_experience(obs, action, reward, done)
            collector.record_step(total_steps, info)
            viz.update(total_steps, info)

            obs = next_obs
            episode_reward += reward
            episode_steps += 1
            total_steps += 1

        collector.end_episode(ep)
        mean_reward = episode_reward / max(episode_steps, 1)

        if mean_reward > best_mean_reward:
            best_mean_reward = mean_reward
            agent.save(os.path.join(output_dir, "models", "ppo_best.pth"))

        if agent.should_update():
            agent.update()

        if ep % 50 == 0:
            print(f"  Episode {ep:4d} | "
                  f"Mean Reward: {mean_reward:+.3f} | "
                  f"Best: {best_mean_reward:+.3f}")

        if ep % config.get("experiment.save_interval_episodes", 50) == 0:
            agent.save(os.path.join(output_dir, "models", f"ppo_ep{ep}.pth"))

    return collector, viz


def main():
    args = parse_args()

    # 中文注释。
    config = load_config(args.config)
    output_dir = args.output_dir
    os.makedirs(os.path.join(output_dir, "models"), exist_ok=True)
    os.makedirs(os.path.join(output_dir, "summary"), exist_ok=True)
    os.makedirs(os.path.join(output_dir, "plots"), exist_ok=True)

    set_seed(args.seed)
    print(f"Seed: {args.seed}")
    print(f"Device: {'cuda' if torch.cuda.is_available() else 'cpu'}")

    # 中文注释。
    num_paths = config.get("network.num_links", 3)
    agent = PPOAgent(
        num_paths=num_paths,
        state_dim=num_paths * 4,
        config=config.get("rl", {}),
    )

    # 中文注释。
    if args.resume and os.path.exists(args.resume):
        agent.load(args.resume)
        print(f"Resumed from {args.resume} (update_count={agent.update_count})")

    # 中文注释。
    start_time = time.time()

    if args.curriculum:
        collector, viz = train_curriculum(agent, output_dir, config, args)
    else:
        env = CovertMultiPathEnv(
            num_links=num_paths,
            scenario=args.scenario,
            max_steps=config.get("experiment.steps_per_episode", 500),
            message_size_bytes=config.get("experiment.message_size_bytes", 16),
        )
        collector = MetricsCollector()
        viz = ExperimentVisualizer(num_paths=num_paths)
        collector, viz = train_single_scenario(agent, env, collector, viz, args, config)
        env.close()

    elapsed = time.time() - start_time
    print(f"\nTraining finished in {elapsed:.1f}s")

    # 中文注释。
    collector.export_summary(os.path.join(output_dir, "summary", "final_results.json"))
    viz.generate_all_plots(os.path.join(output_dir, "plots"))

    # 中文注释。
    overall = collector._compute_overall_metrics()
    print("\nFinal Training Results:")
    for key, val in overall.items():
        print(f"  {key}: {val}")

    agent.save(os.path.join(output_dir, "models", "ppo_final.pth"))
    print(f"\nModel saved to {os.path.join(output_dir, 'models', 'ppo_final.pth')}")


if __name__ == "__main__":
    main()
