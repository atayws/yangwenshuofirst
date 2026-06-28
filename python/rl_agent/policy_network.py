"""
PPO 使用的策略网络和价值网络。
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Tuple


class PolicyNetwork(nn.Module):
    """
    PolicyNetwork 类。
    """

    def __init__(
        self,
        state_dim: int,
        num_paths: int,
        num_strategies: int = 5,
        hidden_dim: int = 128,
    ):
        """
        __init__ 函数。
        """
        super().__init__()
        self.state_dim = state_dim
        self.num_paths = num_paths
        self.num_strategies = num_strategies

        # 中文注释。
        self.feature_extractor = nn.Sequential(
            nn.Linear(state_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
        )

        # 中文注释。
        # 中文注释。
        self.strategy_head = nn.Linear(
            hidden_dim, num_paths * num_strategies
        )

        # 中文注释。
        self.value_head = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Linear(hidden_dim // 2, 1),
        )

        # 中文注释。
        self._init_weights()

    def forward(self, state: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        forward 函数。
        """
        features = self.feature_extractor(state)

        # 中文注释。
        strategy_logits = self.strategy_head(features)
        strategy_logits = strategy_logits.view(
            -1, self.num_paths, self.num_strategies
        )

        # 中文注释。
        value = self.value_head(features)

        return strategy_logits, value

    def get_strategy_probs(
        self, state: torch.Tensor
    ) -> torch.distributions.Categorical:
        """
        get_strategy_probs 函数。
        """
        logits, _ = self.forward(state)
        # 中文注释。
        logits_flat = logits.view(-1, self.num_strategies)
        return torch.distributions.Categorical(logits=logits_flat)

    def get_action(
        self, state: torch.Tensor, deterministic: bool = False
    ) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        get_action 函数。
        """
        logits, value = self.forward(state)

        # 中文注释。
        logits_flat = logits.view(-1, self.num_strategies)
        dist = torch.distributions.Categorical(logits=logits_flat)

        if deterministic:
            action = torch.argmax(logits_flat, dim=-1)
        else:
            action = dist.sample()

        log_prob = dist.log_prob(action).sum()  # 中文注释。

        return action, log_prob, value.squeeze(-1)

    def evaluate(
        self, state: torch.Tensor, action: torch.Tensor
    ) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        evaluate 函数。
        """
        logits, value = self.forward(state)

        batch_size = logits.shape[0]
        logits_flat = logits.view(batch_size * self.num_paths, self.num_strategies)
        action_flat = action.view(-1)

        dist = torch.distributions.Categorical(logits=logits_flat)
        log_prob = dist.log_prob(action_flat)
        log_prob = log_prob.view(batch_size, self.num_paths).sum(dim=-1)
        entropy = dist.entropy().view(batch_size, self.num_paths).sum(dim=-1)

        return log_prob, entropy, value.squeeze(-1)

    def _init_weights(self):
        """_init_weights 函数。"""
        for module in self.modules():
            if isinstance(module, nn.Linear):
                nn.init.orthogonal_(module.weight, gain=nn.init.calculate_gain("relu"))
                nn.init.constant_(module.bias, 0.0)

        # 中文注释。
        nn.init.orthogonal_(
            self.strategy_head.weight, gain=0.01
        )
        nn.init.constant_(self.strategy_head.bias, 0.0)


class ValueNetwork(nn.Module):
    """
    ValueNetwork 类。
    """

    def __init__(self, state_dim: int, hidden_dim: int = 128):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(state_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Linear(hidden_dim // 2, 1),
        )

        # 中文注释。
        for module in self.net:
            if isinstance(module, nn.Linear):
                nn.init.orthogonal_(
                    module.weight, gain=nn.init.calculate_gain("relu")
                )
                nn.init.constant_(module.bias, 0.0)

    def forward(self, state: torch.Tensor) -> torch.Tensor:
        return self.net(state).squeeze(-1)
