"""
实验指标收集与汇总。
"""

import json
import time
from collections import defaultdict
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional
import numpy as np


@dataclass
class StepMetrics:
    """StepMetrics 类。"""
    step: int
    timestamp: float

    # 中文注释。
    throughput_bps: float = 0.0
    success_ratio: float = 0.0
    bytes_sent: int = 0
    bytes_delivered: int = 0

    # 中文注释。
    detected: bool = False
    anomaly_score: float = 0.0

    # 中文注释。
    reward: float = 0.0
    strategy_ids: List[int] = None

    # 中文注释。
    path_delay_ms: Dict[int, float] = None
    path_jitter_ms: Dict[int, float] = None
    path_loss_rate: Dict[int, float] = None

    def __post_init__(self):
        if self.strategy_ids is None:
            self.strategy_ids = []
        if self.path_delay_ms is None:
            self.path_delay_ms = {}
        if self.path_jitter_ms is None:
            self.path_jitter_ms = {}
        if self.path_loss_rate is None:
            self.path_loss_rate = {}


class MetricsCollector:
    """
    MetricsCollector 类。
    """

    def __init__(self):
        self._steps: List[StepMetrics] = []
        self._episodes: List[dict] = []
        self._start_time: float = time.time()

        # 中文注释。
        self._running: Dict[str, List[float]] = defaultdict(list)

    def record_step(self, step: int, metrics: Dict[str, Any]):
        """
        record_step 函数。
        """
        sm = StepMetrics(
            step=step,
            timestamp=time.time() - self._start_time,
            throughput_bps=metrics.get("throughput_bps", 0.0),
            success_ratio=metrics.get("success_ratio", 0.0),
            bytes_sent=metrics.get("bytes_sent", 0),
            bytes_delivered=metrics.get("bytes_delivered", 0),
            detected=metrics.get("detected", False),
            anomaly_score=metrics.get("anomaly_score", 0.0),
            reward=metrics.get("reward", 0.0),
            strategy_ids=metrics.get("strategies_used", []),
            path_delay_ms=metrics.get("path_delay_ms", {}),
            path_jitter_ms=metrics.get("path_jitter_ms", {}),
            path_loss_rate=metrics.get("path_loss_rate", {}),
        )

        self._steps.append(sm)

        # 中文注释。
        self._running["throughput"].append(sm.throughput_bps)
        self._running["reward"].append(sm.reward)
        self._running["success_ratio"].append(sm.success_ratio)
        if sm.detected:
            self._running["detected_count"].append(1)
        else:
            self._running["detected_count"].append(0)

    def end_episode(self, episode: int, extra: Optional[dict] = None):
        """
        end_episode 函数。
        """
        if not self._steps:
            return

        episode_steps = len(self._steps)
        episode_summary = {
            "episode": episode,
            "steps": episode_steps,
            "mean_reward": float(np.mean(self._running["reward"])),
            "std_reward": float(np.std(self._running["reward"])),
            "total_reward": float(np.sum(self._running["reward"])),
            "mean_throughput_bps": float(np.mean(self._running["throughput"])),
            "mean_success_ratio": float(np.mean(self._running["success_ratio"])),
            "detection_rate": float(np.mean(self._running["detected_count"])),
            "strategy_distribution": self._compute_strategy_distribution(),
        }

        if extra:
            episode_summary.update(extra)

        self._episodes.append(episode_summary)

        # 中文注释。
        for key in self._running:
            self._running[key].clear()

    def export_summary(self, filepath: str):
        """
        export_summary 函数。
        """
        summary = {
            "experiment_duration_s": time.time() - self._start_time,
            "total_steps": len(self._steps),
            "total_episodes": len(self._episodes),
            "episodes": self._episodes,
            "overall_metrics": self._compute_overall_metrics(),
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)

    def get_recent_metrics(self, window: int = 10) -> dict:
        """get_recent_metrics 函数。"""
        recent = self._steps[-window:] if len(self._steps) >= window else self._steps
        if not recent:
            return {}

        return {
            "throughput_bps": np.mean([s.throughput_bps for s in recent]),
            "success_ratio": np.mean([s.success_ratio for s in recent]),
            "reward": np.mean([s.reward for s in recent]),
            "detection_rate": np.mean([1 if s.detected else 0 for s in recent]),
        }

    def _compute_strategy_distribution(self) -> Dict[int, float]:
        """_compute_strategy_distribution 函数。"""
        counts = np.zeros(5, dtype=int)
        for sm in self._steps:
            for sid in sm.strategy_ids:
                if 0 <= sid < 5:
                    counts[sid] += 1
        total = counts.sum()
        if total == 0:
            return {}
        return {int(i): float(counts[i] / total) for i in range(5)}

    def _compute_overall_metrics(self) -> dict:
        """_compute_overall_metrics 函数。"""
        if not self._episodes:
            return {}

        rewards = [e["mean_reward"] for e in self._episodes]
        throughputs = [e["mean_throughput_bps"] for e in self._episodes]
        detection_rates = [e["detection_rate"] for e in self._episodes]

        return {
            "num_episodes": len(self._episodes),
            "mean_reward_per_episode": float(np.mean(rewards)),
            "final_reward": float(rewards[-1]) if rewards else 0.0,
            "mean_throughput_bps": float(np.mean(throughputs)),
            "mean_detection_rate": float(np.mean(detection_rates)),
            "reward_convergence": float(np.polyfit(range(len(rewards)), rewards, 1)[0])
                if len(rewards) > 1 else 0.0,  # 中文注释。
        }

    def clear(self):
        """clear 函数。"""
        self._steps.clear()
        self._episodes.clear()
        for key in self._running:
            self._running[key].clear()
        self._start_time = time.time()
