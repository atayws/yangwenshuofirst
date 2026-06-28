"""
隐蔽性、可靠性和吞吐量的多目标奖励计算。
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
import numpy as np


@dataclass
class RewardWeights:
    """RewardWeights 类。"""
    covertness: float = 0.40
    reliability: float = 0.35
    throughput: float = 0.25

    def validate(self):
        """validate 函数。"""
        total = self.covertness + self.reliability + self.throughput
        if abs(total - 1.0) > 0.01:
            # 中文注释。
            self.covertness /= total
            self.reliability /= total
            self.throughput /= total


@dataclass
class TransmissionFeedback:
    """
    TransmissionFeedback 类。
    """
    # 中文注释。
    detected: bool = False

    # 中文注释。
    success_ratio: float = 1.0        # 中文注释。
    bytes_delivered: int = 0          # 中文注释。
    bytes_total: int = 0              # 中文注释。

    # 中文注释。
    throughput_bps: float = 0.0       # 中文注释。
    target_throughput_bps: float = 100.0  # 中文注释。

    # 中文注释。
    path_success: Dict[int, bool] = field(default_factory=dict)

    # 中文注释。
    avg_latency_ms: float = 0.0
    strategy_distribution: Dict[int, int] = field(default_factory=dict)


class RewardCalculator:
    """
    RewardCalculator 类。
    """

    def __init__(
        self,
        weights: Optional[RewardWeights] = None,
        detection_penalty: float = -2.0,
        success_bonus: float = 1.0,
        throughput_saturation: float = 200.0,  # 中文注释。
    ):
        """
        __init__ 函数。
        """
        self.weights = weights or RewardWeights()
        self.weights.validate()
        self.detection_penalty = detection_penalty
        self.success_bonus = success_bonus
        self.throughput_saturation = throughput_saturation

        # 中文注释。
        self._prev_strategies: Optional[np.ndarray] = None
        self._prev_success_ratio: float = 0.0

    def compute(
        self,
        feedback: TransmissionFeedback,
        current_strategies: Optional[np.ndarray] = None,
    ) -> float:
        """
        计算当前反馈对应的标量奖励。
        """
        # 中文注释。
        covertness_reward = self._compute_covertness(feedback.detected)

        # 中文注释。
        reliability_reward = self._compute_reliability(feedback.success_ratio)

        # 中文注释。
        throughput_reward = self._compute_throughput(
            feedback.throughput_bps, feedback.target_throughput_bps
        )

        # 中文注释。
        shaping_reward = 0.0
        if current_strategies is not None:
            shaping_reward += self._compute_strategy_diversity_bonus(
                current_strategies
            )
            shaping_reward += self._compute_stability_penalty(
                current_strategies
            )

        # 中文注释。
        total = (
            self.weights.covertness * covertness_reward
            + self.weights.reliability * reliability_reward
            + self.weights.throughput * throughput_reward
            + 0.05 * shaping_reward  # 中文注释。
        )

        return float(np.clip(total, -2.0, 2.0))

    def _compute_covertness(self, detected: bool) -> float:
        """
        _compute_covertness 函数。
        """
        if detected:
            return self.detection_penalty  # 中文注释。
        else:
            return 1.0  # 中文注释。

    def _compute_reliability(self, success_ratio: float) -> float:
        """
        _compute_reliability 函数。
        """
        return self.success_bonus * (2.0 * success_ratio - 1.0)

    def _compute_throughput(
        self, actual_bps: float, target_bps: float
    ) -> float:
        """
        _compute_throughput 函数。
        """
        normalized = actual_bps / max(target_bps, 1.0)
        # 中文注释。
        return np.tanh(normalized)

    def _compute_strategy_diversity_bonus(
        self, strategies: np.ndarray
    ) -> float:
        """
        _compute_strategy_diversity_bonus 函数。
        """
        unique = len(set(strategies.tolist()))
        diversity = unique / len(strategies)  # 中文注释。
        # 中文注释。
        return (diversity - 0.5) * 0.6

    def _compute_stability_penalty(
        self, strategies: np.ndarray
    ) -> float:
        """
        _compute_stability_penalty 函数。
        """
        if self._prev_strategies is None:
            self._prev_strategies = strategies.copy()
            return 0.0

        # 中文注释。
        changes = np.sum(strategies != self._prev_strategies)
        self._prev_strategies = strategies.copy()

        # 中文注释。
        return -0.05 * changes

    def reset(self):
        """重置内部状态并返回初始观测。"""
        self._prev_strategies = None
        self._prev_success_ratio = 0.0
