"""
实验过程和结果可视化。
"""

import os
from collections import defaultdict
from typing import Dict, List, Optional, Tuple
import numpy as np

# 中文注释。
try:
    import matplotlib
    matplotlib.use("Agg")  # 中文注释。
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False


class ExperimentVisualizer:
    """
    ExperimentVisualizer 类。
    """

    def __init__(self, num_paths: int = 3):
        self.num_paths = num_paths

        # 中文注释。
        self._steps: List[int] = []
        self._rewards: List[float] = []
        self._throughputs: List[float] = []
        self._success_ratios: List[float] = []
        self._detection_flags: List[int] = []
        self._strategy_history: Dict[int, List[int]] = defaultdict(list)
        self._path_delays: Dict[int, List[float]] = defaultdict(list)
        self._path_losses: Dict[int, List[float]] = defaultdict(list)

    def update(self, step: int, metrics: dict):
        """
        update 函数。
        """
        self._steps.append(step)
        self._rewards.append(metrics.get("reward", 0.0))
        self._throughputs.append(metrics.get("throughput_bps", 0.0))
        self._success_ratios.append(metrics.get("success_ratio", 0.0))
        self._detection_flags.append(1 if metrics.get("detected", False) else 0)

        strategies = metrics.get("strategies_used", [])
        for pid, sid in enumerate(strategies):
            self._strategy_history[pid].append(sid)

        path_delays = metrics.get("path_delay_ms", {})
        for pid, delay in path_delays.items():
            self._path_delays[pid].append(delay)

        path_losses = metrics.get("path_loss_rate", {})
        for pid, loss in path_losses.items():
            self._path_losses[pid].append(loss)

    def generate_all_plots(self, save_dir: str = "experiments/results/plots/"):
        """generate_all_plots 函数。"""
        if not HAS_MATPLOTLIB:
            print("Matplotlib not available. Skipping visualization.")
            return

        os.makedirs(save_dir, exist_ok=True)

        self._plot_reward(save_dir)
        self._plot_performance(save_dir)
        self._plot_strategy_usage(save_dir)
        self._plot_path_conditions(save_dir)
        self._plot_detection_rate(save_dir)

        plt.close("all")

    def _plot_reward(self, save_dir: str):
        """_plot_reward 函数。"""
        fig, ax = plt.subplots(figsize=(10, 4))
        ax.plot(self._steps, self._rewards, alpha=0.6, linewidth=0.5, color="blue",
                label="Step Reward")

        # 中文注释。
        if len(self._rewards) > 10:
            alpha = 0.05
            smoothed = [self._rewards[0]]
            for r in self._rewards[1:]:
                smoothed.append(alpha * r + (1 - alpha) * smoothed[-1])
            ax.plot(self._steps, smoothed, linewidth=2, color="red",
                    label="Smoothed (EMA)")

        ax.axhline(y=0, color="gray", linestyle="--", linewidth=0.5)
        ax.set_xlabel("Step")
        ax.set_ylabel("Reward")
        ax.set_title("RL Training: Reward over Time")
        ax.legend()
        ax.grid(True, alpha=0.3)
        fig.tight_layout()
        fig.savefig(os.path.join(save_dir, "reward_curve.png"), dpi=150)

    def _plot_performance(self, save_dir: str):
        """_plot_performance 函数。"""
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4))

        ax1.plot(self._steps, self._throughputs, alpha=0.6, linewidth=0.5,
                 color="green")
        ax1.set_xlabel("Step")
        ax1.set_ylabel("Throughput (bps)")
        ax1.set_title("Covert Throughput")
        ax1.grid(True, alpha=0.3)

        ax2.plot(self._steps, self._success_ratios, alpha=0.6, linewidth=0.5,
                 color="blue")
        ax2.set_xlabel("Step")
        ax2.set_ylabel("Success Ratio")
        ax2.set_title("Message Decode Success Rate")
        ax2.set_ylim(0, 1.05)
        ax2.grid(True, alpha=0.3)

        fig.tight_layout()
        fig.savefig(os.path.join(save_dir, "performance.png"), dpi=150)

    def _plot_strategy_usage(self, save_dir: str):
        """_plot_strategy_usage 函数。"""
        fig, ax = plt.subplots(figsize=(10, 4))

        # 中文注释。
        strategy_counts = np.zeros((len(self._steps), 5))
        for pid, history in self._strategy_history.items():
            for i, sid in enumerate(history):
                if i < len(self._steps) and 0 <= sid < 5:
                    strategy_counts[i, sid] += 1

        # 中文注释。
        for i in range(len(strategy_counts)):
            total = strategy_counts[i].sum()
            if total > 0:
                strategy_counts[i] /= total

        # 中文注释。
        cumulative = np.cumsum(strategy_counts, axis=1)

        colors = ["#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd"]
        labels = [
            "Timing-HC (0)", "Timing-HCap (1)", "Protocol (2)",
            "Statistical (3)", "Redundancy (4)",
        ]

        for i in range(5):
            if i == 0:
                ax.fill_between(self._steps, 0, cumulative[:, i],
                                alpha=0.7, color=colors[i], label=labels[i])
            else:
                ax.fill_between(self._steps, cumulative[:, i - 1], cumulative[:, i],
                                alpha=0.7, color=colors[i], label=labels[i])

        ax.set_xlabel("Step")
        ax.set_ylabel("Strategy Proportion")
        ax.set_title("Strategy Usage over Time")
        ax.set_ylim(0, 1)
        ax.legend(loc="upper right")
        ax.grid(True, alpha=0.3)
        fig.tight_layout()
        fig.savefig(os.path.join(save_dir, "strategy_usage.png"), dpi=150)

    def _plot_path_conditions(self, save_dir: str):
        """_plot_path_conditions 函数。"""
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4))

        colors = ["blue", "orange", "green", "red", "purple"]

        for pid in range(self.num_paths):
            if pid in self._path_delays and self._path_delays[pid]:
                # 中文注释。
                delays = self._path_delays[pid]
                xs = self._steps[:len(delays)]
                ax1.plot(xs, delays, alpha=0.5, linewidth=0.8,
                         color=colors[pid % len(colors)], label=f"Path {pid}")

            if pid in self._path_losses and self._path_losses[pid]:
                losses = self._path_losses[pid]
                xs = self._steps[:len(losses)]
                ax2.plot(xs, losses, alpha=0.5, linewidth=0.8,
                         color=colors[pid % len(colors)], label=f"Path {pid}")

        ax1.set_xlabel("Step")
        ax1.set_ylabel("Delay (ms)")
        ax1.set_title("Per-Path Delay")
        ax1.legend()
        ax1.grid(True, alpha=0.3)

        ax2.set_xlabel("Step")
        ax2.set_ylabel("Loss Rate")
        ax2.set_title("Per-Path Loss Rate")
        ax2.legend()
        ax2.grid(True, alpha=0.3)

        fig.tight_layout()
        fig.savefig(os.path.join(save_dir, "path_conditions.png"), dpi=150)

    def _plot_detection_rate(self, save_dir: str):
        """_plot_detection_rate 函数。"""
        fig, ax = plt.subplots(figsize=(10, 4))

        window = min(50, len(self._detection_flags))
        if window > 1:
            # 中文注释。
            detection_array = np.array(self._detection_flags)
            rolling = np.convolve(
                detection_array,
                np.ones(window) / window,
                mode="valid",
            )
            valid_steps = self._steps[window - 1:]

            ax.plot(valid_steps, rolling, linewidth=1.5, color="red")
            ax.axhline(y=0.5, color="gray", linestyle="--", linewidth=0.5,
                       label="50% threshold")

        ax.set_xlabel("Step")
        ax.set_ylabel("Detection Rate (rolling)")
        ax.set_title("Covertness Detection Rate")
        ax.set_ylim(0, 1.05)
        ax.legend()
        ax.grid(True, alpha=0.3)
        fig.tight_layout()
        fig.savefig(os.path.join(save_dir, "detection_rate.png"), dpi=150)
