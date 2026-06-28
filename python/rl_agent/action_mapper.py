"""
强化学习动作与路径策略分配之间的转换。
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
import numpy as np


@dataclass
class StrategyAssignment:
    """StrategyAssignment 类。"""
    path_id: int
    strategy_id: int
    params: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "path_id": self.path_id,
            "strategy_id": self.strategy_id,
            "params": self.params,
        }


class ActionMapper:
    """
    ActionMapper 类。
    """

    def __init__(
        self,
        num_paths: int = 3,
        strategy_defaults: Optional[Dict[int, dict]] = None,
    ):
        """
        __init__ 函数。
        """
        self.num_paths = num_paths
        self._defaults = strategy_defaults or self._get_default_params()

    def map_to_assignments(
        self, action: np.ndarray
    ) -> Dict[int, StrategyAssignment]:
        """
        map_to_assignments 函数。
        """
        assignments = {}

        for path_id in range(self.num_paths):
            if path_id < len(action):
                strategy_id = int(action[path_id])
            else:
                strategy_id = 0  # 中文注释。

            # 中文注释。
            strategy_id = max(0, min(4, strategy_id))

            params = self._get_strategy_params(strategy_id)

            assignments[path_id] = StrategyAssignment(
                path_id=path_id,
                strategy_id=strategy_id,
                params=params,
            )

        return assignments

    def assignments_to_action(
        self, assignments: Dict[int, StrategyAssignment]
    ) -> np.ndarray:
        """
        assignments_to_action 函数。
        """
        action = np.zeros(self.num_paths, dtype=np.int32)
        for path_id, a in assignments.items():
            if path_id < self.num_paths:
                action[path_id] = a.strategy_id
        return action

    def action_to_indices(
        self, action: np.ndarray
    ) -> List[Tuple[int, int]]:
        """
        action_to_indices 函数。
        """
        result = []
        for path_id in range(min(self.num_paths, len(action))):
            result.append((path_id, int(action[path_id])))
        return result

    def random_action(self) -> np.ndarray:
        """random_action 函数。"""
        return np.random.randint(0, 5, size=self.num_paths, dtype=np.int32)

    def _get_strategy_params(self, strategy_id: int) -> dict:
        """_get_strategy_params 函数。"""
        defaults = self._defaults.get(strategy_id, {}).copy()
        return defaults

    @staticmethod
    def _get_default_params() -> Dict[int, dict]:
        """_get_default_params 函数。"""
        return {
            0: {  # 中文注释。
                "gap_0_ms": 20,
                "gap_1_ms": 100,
                "max_jitter_tolerance_ms": 15,
            },
            1: {  # 中文注释。
                "levels_ms": [25, 75, 125, 150],
                "max_jitter_tolerance_ms": 10,
            },
            2: {  # 中文注释。
                "rs_n": 6,
                "rs_k": 4,
            },
            3: {  # 中文注释。
                "length_bands": [
                    [96, 160],
                    [320, 520],
                    [720, 940],
                    [1100, 1360],
                ],
                "header_overhead_bytes": 40,
                "min_band_gap_bytes": 24,
            },
            4: {  # 中文注释。
                "rs_m": 3,
                "rs_c": 2,
                "chunk_size_bytes": 32,
            },
        }
