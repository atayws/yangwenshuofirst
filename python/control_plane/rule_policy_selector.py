"""
阶段二规则策略选择器。

该模块把 INT 输出的链路状态转换成可执行的隐蔽策略计划。后续接入 PPO 时，
只需要让 PPO 输出同样的 PolicyEntry 列表即可复用现有 live 收发器。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping

from experiments.verify_manual_policy_session import PolicyEntry, validate_plan


@dataclass(frozen=True)
class LinkScore:
    """单条链路的规则评分结果。"""

    path_id: int
    delay_ms: float
    jitter_ms: float
    loss_rate: float
    bw_utilization: float
    score: float


class RuleBasedPolicySelector:
    """根据 INT 链路状态生成阶段二策略计划。"""

    def __init__(
        self,
        max_strategy3_loss: float = 0.03,
        max_strategy3_jitter_ms: float = 8.0,
        max_usable_loss: float = 0.35,
    ):
        self.max_strategy3_loss = float(max_strategy3_loss)
        self.max_strategy3_jitter_ms = float(max_strategy3_jitter_ms)
        self.max_usable_loss = float(max_usable_loss)

    def select(self, path_states: Mapping[int, object]) -> List[PolicyEntry]:
        """把 path_states 转换为可供 live 脚本执行的策略计划。"""
        scores = self.score_paths(path_states)
        if not scores:
            plan = [
                PolicyEntry("fallback_path0_s0", 0, (0,), 1),
                PolicyEntry("fallback_path1_s1", 1, (1,), 1),
                PolicyEntry("fallback_path0_s2", 2, (0,), 1),
                PolicyEntry("fallback_path2_s3", 3, (2,), 1),
                PolicyEntry("fallback_path01_s4", 4, (0, 1), 1),
                PolicyEntry("fallback_path012_s5", 5, (0, 1, 2), 1),
            ]
            validate_plan(plan)
            return plan

        usable = [item for item in scores if item.loss_rate <= self.max_usable_loss]
        if not usable:
            usable = scores[:]
        usable = sorted(usable, key=lambda item: item.score, reverse=True)

        plan: List[PolicyEntry] = []
        timing_safe = [
            item for item in usable
            if item.loss_rate <= 0.0001 and item.jitter_ms <= 2.0 and item.delay_ms <= 80.0
        ]
        if timing_safe:
            best = timing_safe[0]
            plan.append(PolicyEntry(f"path{best.path_id}_timing_s0", 0, (best.path_id,), 1))
        all_clean = all(item.loss_rate <= 0.0001 for item in usable)
        if all_clean and len(timing_safe) >= 2:
            second = timing_safe[1]
            plan.append(PolicyEntry(f"path{second.path_id}_timing_s1", 1, (second.path_id,), 1))

        used_paths = {path for entry in plan for path in entry.paths}
        for item in usable:
            if item.path_id in used_paths:
                continue
            strategy_id = self._strategy_for_path(item)
            plan.append(
                PolicyEntry(
                    name=f"path{item.path_id}_auto_s{strategy_id}",
                    strategy_id=strategy_id,
                    paths=(item.path_id,),
                    weight=max(1, self._weight_for_score(item.score)),
                )
            )
            used_paths.add(item.path_id)
            if len(plan) >= 4:
                break

        fountain_paths = tuple(item.path_id for item in usable[:3])
        if len(fountain_paths) >= 2:
            plan.append(
                PolicyEntry(
                    name="auto_fountain_s4_" + "".join(str(path) for path in fountain_paths),
                    strategy_id=4,
                    paths=fountain_paths,
                    weight=1,
                )
            )

        sequence_paths = tuple(
            item.path_id for item in usable
            if item.loss_rate <= 0.005 and item.jitter_ms <= 10.0
        )
        if len(sequence_paths) >= 3:
            plan.append(
                PolicyEntry(
                    name="auto_path_sequence_s5_" + "".join(str(path) for path in sequence_paths[:3]),
                    strategy_id=5,
                    paths=sequence_paths[:3],
                    weight=1,
                )
            )

        validate_plan(plan)
        return plan

    def score_paths(self, path_states: Mapping[int, object]) -> List[LinkScore]:
        """计算每条链路的可用性评分。"""
        scores: List[LinkScore] = []
        for raw_path_id, state in path_states.items():
            path_id = int(raw_path_id)
            delay_ms = float(self._get(state, "delay_ms", 0.0))
            jitter_ms = float(self._get(state, "jitter_ms", 0.0))
            loss_rate = float(self._get(state, "loss_rate", 0.0))
            bw_utilization = float(self._get(state, "bw_utilization", 0.0))
            score = (
                1.0
                - min(delay_ms / 100.0, 1.0) * 0.30
                - min(jitter_ms / 30.0, 1.0) * 0.20
                - min(loss_rate / 0.30, 1.0) * 0.35
                - min(bw_utilization, 1.0) * 0.15
            )
            scores.append(
                LinkScore(
                    path_id=path_id,
                    delay_ms=delay_ms,
                    jitter_ms=jitter_ms,
                    loss_rate=loss_rate,
                    bw_utilization=bw_utilization,
                    score=max(0.0, score),
                )
            )
        return sorted(scores, key=lambda item: item.score, reverse=True)

    def _strategy_for_path(self, score: LinkScore) -> int:
        if (
            score.loss_rate <= self.max_strategy3_loss
            and score.jitter_ms <= self.max_strategy3_jitter_ms
            and score.delay_ms <= 80.0
        ):
            return 3
        return 2

    @staticmethod
    def _weight_for_score(score: float) -> int:
        if score >= 0.80:
            return 2
        return 1

    @staticmethod
    def _get(state: object, key: str, default: float) -> float:
        if isinstance(state, Mapping):
            return float(state.get(key, default))
        return float(getattr(state, key, default))


def plan_to_dicts(plan: Iterable[PolicyEntry]) -> List[dict]:
    """把策略计划转换为字典列表。"""
    return [entry.to_dict() for entry in plan]
