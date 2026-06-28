"""
PPO 经验缓存和 GAE 优势计算。
"""

import torch
import numpy as np
from typing import Tuple


class RolloutEntry:
    """RolloutEntry 类。"""

    __slots__ = [
        "state", "action", "reward", "done",
        "value", "log_prob",
    ]

    def __init__(
        self,
        state: np.ndarray,
        action: np.ndarray,
        reward: float,
        done: bool,
        value: float,
        log_prob: float,
    ):
        self.state = state
        self.action = action
        self.reward = reward
        self.done = done
        self.value = value
        self.log_prob = log_prob


class RolloutBuffer:
    """
    RolloutBuffer 类。
    """

    def __init__(
        self,
        capacity: int = 2048,
        state_dim: int = 12,
        num_paths: int = 3,
        gamma: float = 0.99,
        gae_lambda: float = 0.95,
    ):
        """
        __init__ 函数。
        """
        self.capacity = capacity
        self.state_dim = state_dim
        self.num_paths = num_paths
        self.gamma = gamma
        self.gae_lambda = gae_lambda

        # 中文注释。
        self.states = np.zeros((capacity, state_dim), dtype=np.float32)
        self.actions = np.zeros((capacity, num_paths), dtype=np.int32)
        self.rewards = np.zeros(capacity, dtype=np.float32)
        self.dones = np.zeros(capacity, dtype=np.bool_)
        self.values = np.zeros(capacity, dtype=np.float32)
        self.log_probs = np.zeros(capacity, dtype=np.float32)

        # 中文注释。
        self.returns = np.zeros(capacity, dtype=np.float32)
        self.advantages = np.zeros(capacity, dtype=np.float32)

        self._ptr = 0
        self._filled = False

    def add(
        self,
        state: np.ndarray,
        action: np.ndarray,
        reward: float,
        done: bool,
        value: float,
        log_prob: float,
    ):
        """
        add 函数。
        """
        self.states[self._ptr] = state
        self.actions[self._ptr] = action
        self.rewards[self._ptr] = reward
        self.dones[self._ptr] = done
        self.values[self._ptr] = value
        self.log_probs[self._ptr] = log_prob

        self._ptr += 1
        if self._ptr >= self.capacity:
            self._filled = True
            self._ptr = 0

    def compute_returns_and_advantages(
        self,
        last_value: float,
        last_done: bool = False,
        normalize_advantages: bool = True,
    ) -> Tuple[
        torch.Tensor, torch.Tensor, torch.Tensor,
        torch.Tensor, torch.Tensor,
    ]:
        """
        compute_returns_and_advantages 函数。
        """
        n = self.size

        # 中文注释。
        gae = 0.0
        for i in reversed(range(n)):
            if i == n - 1:
                next_value = 0.0 if last_done else last_value
                next_done = last_done
            else:
                next_value = self.values[i + 1]
                next_done = self.dones[i]

            # 中文注释。
            delta = (
                self.rewards[i]
                + self.gamma * next_value * (1.0 - float(next_done))
                - self.values[i]
            )

            # 中文注释。
            gae = delta + self.gamma * self.gae_lambda * (1.0 - float(self.dones[i])) * gae
            self.advantages[i] = gae
            self.returns[i] = self.advantages[i] + self.values[i]

        # 中文注释。
        if normalize_advantages and n > 1:
            adv_mean = np.mean(self.advantages[:n])
            adv_std = np.std(self.advantages[:n])
            self.advantages[:n] = (self.advantages[:n] - adv_mean) / (adv_std + 1e-8)

        # 中文注释。
        states = torch.FloatTensor(self.states[:n])
        actions = torch.LongTensor(self.actions[:n])
        returns = torch.FloatTensor(self.returns[:n])
        advantages = torch.FloatTensor(self.advantages[:n])
        old_log_probs = torch.FloatTensor(self.log_probs[:n])

        return states, actions, returns, advantages, old_log_probs

    def sample_minibatches(
        self,
        batch_size: int = 64,
    ) -> list:
        """
        sample_minibatches 函数。
        """
        n = self.size
        indices = np.random.permutation(n)

        batches = []
        for start in range(0, n, batch_size):
            batch_idx = indices[start : start + batch_size]

            batches.append((
                torch.FloatTensor(self.states[batch_idx]),
                torch.LongTensor(self.actions[batch_idx]),
                torch.FloatTensor(self.returns[batch_idx]),
                torch.FloatTensor(self.advantages[batch_idx]),
                torch.FloatTensor(self.log_probs[batch_idx]),
            ))

        return batches

    def clear(self):
        """clear 函数。"""
        self._ptr = 0
        self._filled = False
        self.states.fill(0)
        self.actions.fill(0)
        self.rewards.fill(0)
        self.dones.fill(False)
        self.values.fill(0)
        self.log_probs.fill(0)

    @property
    def size(self) -> int:
        """size 函数。"""
        return self.capacity if self._filled else self._ptr

    @property
    def is_full(self) -> bool:
        return self._filled or self._ptr >= self.capacity
