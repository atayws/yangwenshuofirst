"""
用于多路径隐蔽策略选择的 PPO 智能体。
"""

import os
import time
from typing import Dict, List, Optional, Tuple, Any
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim

from .policy_network import PolicyNetwork
from .buffer import RolloutBuffer
from .state_processor import StateProcessor
from .action_mapper import ActionMapper, StrategyAssignment
from .reward_calculator import RewardCalculator, TransmissionFeedback


class PPOAgent:
    """
    用于自适应选择每条路径隐蔽策略的 PPO 智能体。
    """

    def __init__(
        self,
        num_paths: int = 3,
        state_dim: int = 12,
        config: Optional[dict] = None,
    ):
        """
        __init__ 函数。
        """
        cfg = config or {}
        self.num_paths = num_paths
        self.state_dim = state_dim

        # 中文注释。
        self.gamma = cfg.get("gamma", 0.99)
        self.gae_lambda = cfg.get("gae_lambda", 0.95)
        self.clip_epsilon = cfg.get("clip_epsilon", 0.2)
        self.entropy_coef = cfg.get("entropy_coef", 0.01)
        self.value_coef = cfg.get("value_coef", 0.5)
        self.max_grad_norm = cfg.get("max_grad_norm", 0.5)
        self.learning_rate = cfg.get("learning_rate", 3e-4)
        self.update_epochs = cfg.get("update_epochs", 10)
        self.batch_size = cfg.get("batch_size", 64)
        self.buffer_capacity = cfg.get("buffer_size", 2048)

        # 中文注释。
        hidden_dim = cfg.get("hidden_dim", 128)
        self.policy = PolicyNetwork(
            state_dim=state_dim,
            num_paths=num_paths,
            num_strategies=5,
            hidden_dim=hidden_dim,
        )

        # 中文注释。
        self.optimizer = optim.Adam(
            self.policy.parameters(),
            lr=self.learning_rate,
            eps=1e-5,
        )

        # 中文注释。
        self.buffer = RolloutBuffer(
            capacity=self.buffer_capacity,
            state_dim=state_dim,
            num_paths=num_paths,
            gamma=self.gamma,
            gae_lambda=self.gae_lambda,
        )

        # 中文注释。
        self.state_processor = StateProcessor(num_paths=num_paths)
        self.action_mapper = ActionMapper(num_paths=num_paths)
        self.reward_calculator = RewardCalculator()

        # 中文注释。
        self._update_count: int = 0
        self._last_state: Optional[np.ndarray] = None
        self._last_action: Optional[np.ndarray] = None

        # 中文注释。
        self._device = torch.device("cpu")
        self.policy.to(self._device)

        # 中文注释。
        self._metrics: Dict[str, List[float]] = {
            "policy_loss": [],
            "value_loss": [],
            "entropy": [],
            "approx_kl": [],
        }

    # 中文注释。

    def select_action(
        self,
        state: np.ndarray,
        deterministic: bool = False,
    ) -> Tuple[np.ndarray, float, float]:
        """
        select_action 函数。
        """
        # 中文注释。
        state_processed = self.state_processor.process(state)
        state_tensor = torch.FloatTensor(state_processed).unsqueeze(0).to(self._device)

        self.policy.eval()
        with torch.no_grad():
            action, log_prob, value = self.policy.get_action(
                state_tensor, deterministic=deterministic
            )

        action_np = action.cpu().numpy().astype(np.int32)
        log_prob_val = float(log_prob.cpu().item())
        value_val = float(value.cpu().item())

        # 中文注释。
        self._last_state = state_processed
        self._last_action = action_np

        return action_np, log_prob_val, value_val

    def get_strategy_assignments(
        self, state: np.ndarray, deterministic: bool = True
    ) -> Dict[int, StrategyAssignment]:
        """
        get_strategy_assignments 函数。
        """
        action, _, _ = self.select_action(state, deterministic=deterministic)
        return self.action_mapper.map_to_assignments(action)

    # 中文注释。

    def store_experience(
        self,
        state: np.ndarray,
        action: np.ndarray,
        reward: float,
        done: bool,
    ):
        """
        store_experience 函数。
        """
        # 中文注释。
        # 中文注释。
        state_processed = self.state_processor.process(state)
        state_tensor = torch.FloatTensor(state_processed).unsqueeze(0).to(self._device)

        self.policy.eval()
        with torch.no_grad():
            _, log_prob, value = self.policy.get_action(state_tensor)

        self.buffer.add(
            state=state_processed,
            action=action,
            reward=reward,
            done=done,
            value=float(value.cpu().item()),
            log_prob=float(log_prob.cpu().item()),
        )

    # 中文注释。

    def should_update(self) -> bool:
        """should_update 函数。"""
        return self.buffer.size >= self.batch_size

    def update(self) -> dict:
        """
        update 函数。
        """
        if self.buffer.size < self.batch_size:
            return {}

        self.policy.train()

        # 中文注释。
        with torch.no_grad():
            # 中文注释。
            last_state = torch.FloatTensor(self.buffer.states[-1]).unsqueeze(0).to(self._device)
            _, last_value = self.policy(last_state)
            last_value = float(last_value.cpu().item())

        (
            states, actions, returns, advantages, old_log_probs
        ) = self.buffer.compute_returns_and_advantages(
            last_value=last_value,
            last_done=bool(self.buffer.dones[-1]),
            normalize_advantages=True,
        )

        # 中文注释。
        states = states.to(self._device)
        actions = actions.to(self._device)
        returns = returns.to(self._device)
        advantages = advantages.to(self._device)
        old_log_probs = old_log_probs.to(self._device)

        epoch_metrics = {
            "policy_loss": [],
            "value_loss": [],
            "entropy": [],
            "approx_kl": [],
        }

        n = self.buffer.size
        indices = np.arange(n)

        for epoch in range(self.update_epochs):
            np.random.shuffle(indices)

            for start in range(0, n, self.batch_size):
                batch_idx = indices[start : start + self.batch_size]

                batch_states = states[batch_idx]
                batch_actions = actions[batch_idx]
                batch_returns = returns[batch_idx]
                batch_advantages = advantages[batch_idx]
                batch_old_log_probs = old_log_probs[batch_idx]

                # 中文注释。
                new_log_probs, entropy, values = self.policy.evaluate(
                    batch_states, batch_actions
                )

                # 中文注释。
                ratio = torch.exp(new_log_probs - batch_old_log_probs)

                # 中文注释。
                surr1 = ratio * batch_advantages
                surr2 = torch.clamp(
                    ratio, 1.0 - self.clip_epsilon, 1.0 + self.clip_epsilon
                ) * batch_advantages
                policy_loss = -torch.min(surr1, surr2).mean()

                # 中文注释。
                # 中文注释。
                value_loss = nn.functional.mse_loss(values, batch_returns)

                # 中文注释。
                entropy_loss = -entropy.mean()

                # 中文注释。
                total_loss = (
                    policy_loss
                    + self.value_coef * value_loss
                    + self.entropy_coef * entropy_loss
                )

                # 中文注释。
                self.optimizer.zero_grad()
                total_loss.backward()
                nn.utils.clip_grad_norm_(
                    self.policy.parameters(), self.max_grad_norm
                )
                self.optimizer.step()

                # 中文注释。
                with torch.no_grad():
                    approx_kl = ((ratio - 1) - torch.log(ratio)).mean()

                epoch_metrics["policy_loss"].append(float(policy_loss.cpu().item()))
                epoch_metrics["value_loss"].append(float(value_loss.cpu().item()))
                epoch_metrics["entropy"].append(float(-entropy_loss.cpu().item()))
                epoch_metrics["approx_kl"].append(float(approx_kl.cpu().item()))

        # 中文注释。
        avg_metrics = {
            key: float(np.mean(values)) if values else 0.0
            for key, values in epoch_metrics.items()
        }

        # 中文注释。
        for key, val in avg_metrics.items():
            self._metrics[key].append(val)

        self._update_count += 1
        self.buffer.clear()

        self.policy.eval()
        return avg_metrics

    # 中文注释。

    def save(self, path: str):
        """保存模型检查点。"""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        checkpoint = {
            "policy_state_dict": self.policy.state_dict(),
            "optimizer_state_dict": self.optimizer.state_dict(),
            "update_count": self._update_count,
            "hyperparams": {
                "num_paths": self.num_paths,
                "state_dim": self.state_dim,
                "gamma": self.gamma,
                "gae_lambda": self.gae_lambda,
                "clip_epsilon": self.clip_epsilon,
                "learning_rate": self.learning_rate,
            },
            "metrics": self._metrics,
        }
        torch.save(checkpoint, path)

    def load(self, path: str):
        """加载模型检查点。"""
        checkpoint = torch.load(path, map_location=self._device)
        self.policy.load_state_dict(checkpoint["policy_state_dict"])
        self.optimizer.load_state_dict(checkpoint["optimizer_state_dict"])
        self._update_count = checkpoint.get("update_count", 0)
        self._metrics = checkpoint.get("metrics", {})

    # 中文注释。

    @property
    def update_count(self) -> int:
        return self._update_count

    @property
    def metrics(self) -> dict:
        return {k: list(v) for k, v in self._metrics.items()}

    @property
    def buffer_size(self) -> int:
        return self.buffer.size

    def to(self, device: str):
        """to 函数。"""
        self._device = torch.device(device)
        self.policy.to(self._device)
