"""
链路状态归一化和平滑处理。
"""

from collections import deque
from dataclasses import dataclass
from typing import Dict, List, Optional
import numpy as np


@dataclass
class NormalizationParams:
    """NormalizationParams 类。"""
    delay_max_ms: float = 200.0       # 中文注释。
    jitter_max_ms: float = 50.0       # 中文注释。
    loss_max: float = 1.0             # 中文注释。
    bw_max: float = 1.0               # 中文注释。
    queue_depth_max: float = 100.0    # 中文注释。


class StateProcessor:
    """
    StateProcessor 类。
    """

    def __init__(
        self,
        num_paths: int = 3,
        norm_params: Optional[NormalizationParams] = None,
        use_smoothing: bool = True,
        ema_alpha: float = 0.1,
        use_delta_features: bool = False,
    ):
        """
        __init__ 函数。
        """
        self.num_paths = num_paths
        self.norm = norm_params or NormalizationParams()
        self.use_smoothing = use_smoothing
        self.ema_alpha = ema_alpha
        self.use_delta_features = use_delta_features

        # 中文注释。
        self._smoothed_state: Optional[np.ndarray] = None

        # 中文注释。
        self._prev_state: Optional[np.ndarray] = None

    def process(self, raw_state: np.ndarray) -> np.ndarray:
        """
        process 函数。
        """
        # 中文注释。
        normalized = np.zeros_like(raw_state, dtype=np.float32)
        for i in range(self.num_paths):
            base = i * 4
            normalized[base + 0] = np.clip(
                raw_state[base + 0] / self.norm.delay_max_ms, 0.0, 1.0
            )
            normalized[base + 1] = np.clip(
                raw_state[base + 1] / self.norm.jitter_max_ms, 0.0, 1.0
            )
            normalized[base + 2] = np.clip(raw_state[base + 2], 0.0, 1.0)
            normalized[base + 3] = np.clip(raw_state[base + 3], 0.0, 1.0)

        # 中文注释。
        if self.use_smoothing:
            if self._smoothed_state is None:
                self._smoothed_state = normalized.copy()
            else:
                self._smoothed_state = (
                    self.ema_alpha * normalized
                    + (1 - self.ema_alpha) * self._smoothed_state
                )
            output = self._smoothed_state.copy()
        else:
            output = normalized

        # 中文注释。
        if self.use_delta_features and self._prev_state is not None:
            deltas = output - self._prev_state
            output = np.concatenate([output, deltas])

        self._prev_state = output.copy()
        return output.astype(np.float32)

    def process_batch(self, raw_states: np.ndarray) -> np.ndarray:
        """
        process_batch 函数。
        """
        batch_size = raw_states.shape[0]
        processed = np.zeros_like(raw_states, dtype=np.float32)

        for b in range(batch_size):
            processed[b] = self._normalize_single(raw_states[b])

        return processed

    def _normalize_single(self, state: np.ndarray) -> np.ndarray:
        """_normalize_single 函数。"""
        normalized = np.zeros_like(state, dtype=np.float32)
        for i in range(self.num_paths):
            base = i * 4
            normalized[base + 0] = np.clip(state[base + 0] / self.norm.delay_max_ms, 0.0, 1.0)
            normalized[base + 1] = np.clip(state[base + 1] / self.norm.jitter_max_ms, 0.0, 1.0)
            normalized[base + 2] = np.clip(state[base + 2], 0.0, 1.0)
            normalized[base + 3] = np.clip(state[base + 3], 0.0, 1.0)
        return normalized

    def reset(self):
        """重置内部状态并返回初始观测。"""
        self._smoothed_state = None
        self._prev_state = None

    @property
    def state_dim(self) -> int:
        """state_dim 函数。"""
        base_dim = self.num_paths * 4
        if self.use_delta_features:
            return base_dim * 2
        return base_dim
