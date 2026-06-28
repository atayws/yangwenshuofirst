"""
低空多路径网络仿真场景库。
"""

from dataclasses import dataclass, field
from typing import Callable, List
import numpy as np


@dataclass
class LinkCondition:
    """LinkCondition 类。"""
    delay_ms: float = 5.0
    jitter_ms: float = 2.0
    loss_rate: float = 0.001
    bw_utilization: float = 0.3


@dataclass
class ScenarioConfig:
    """ScenarioConfig 类。"""
    name: str
    description: str
    num_links: int = 3
    max_steps: int = 500
    decision_interval_ms: int = 100
    link_conditions: List[Callable[[int], LinkCondition]] = field(default_factory=list)
    detection_sensitivity: float = 0.5


class ScenarioLibrary:
    """ScenarioLibrary 类。"""

    @staticmethod
    def static_good(num_links: int = 3) -> ScenarioConfig:
        bases = [
            LinkCondition(5.0,  2.0,  0.001, 0.30),
            LinkCondition(15.0, 5.0,  0.005, 0.45),
            LinkCondition(30.0, 10.0, 0.010, 0.55),
        ]
        return ScenarioConfig(
            name="static_good",
            description="3 links stable: good / medium / poor quality",
            num_links=num_links, max_steps=500,
            link_conditions=[lambda s, b=b: b for b in bases[:num_links]],
        )

    @staticmethod
    def dynamic_fluctuation(num_links: int = 3) -> ScenarioConfig:
        period = 200
        bases = [(10.0, 2.0, 0.002), (20.0, 5.0, 0.005), (30.0, 10.0, 0.008)]

        def make(bl, bj, bls, ph):
            def fn(step):
                f = 0.5 + 0.5 * np.sin(2 * np.pi * step / period + ph)
                return LinkCondition(bl * (0.5 + f), bj * (0.5 + f), bls * (0.5 + f), 0.3 + 0.4 * f)
            return fn

        return ScenarioConfig(
            name="dynamic_fluctuation",
            description="Sinusoidal link quality variation",
            num_links=num_links, max_steps=500,
            link_conditions=[
                make(bases[0][0], bases[0][1], bases[0][2], 0.0),
                make(bases[1][0], bases[1][1], bases[1][2], 2.094),
                make(bases[2][0], bases[2][1], bases[2][2], 4.189),
            ][:num_links],
        )

    @staticmethod
    def link_failure(num_links: int = 3) -> ScenarioConfig:
        def link_0(s): return LinkCondition(8.0, 3.0, 0.002)
        def link_1(s):
            if 100 <= s < 300:
                return LinkCondition(80.0, 30.0, 0.15, 0.9)
            return LinkCondition(12.0, 4.0, 0.003)
        def link_2(s): return LinkCondition(15.0, 6.0, 0.005)

        return ScenarioConfig(
            name="link_failure",
            description="Link 1 fails from step 100-300",
            num_links=num_links, max_steps=500,
            link_conditions=[link_0, link_1, link_2][:num_links],
            detection_sensitivity=0.3,
        )

    @staticmethod
    def high_mobility(num_links: int = 3) -> ScenarioConfig:
        def make(base_d, seed):
            rng = np.random.RandomState(seed)
            cur = base_d
            def fn(step):
                nonlocal cur
                cur += rng.normal(0, 2.0) - 0.1 * (cur - base_d)
                cur = max(1.0, min(100.0, cur))
                loss = min(0.20, max(0.001, 0.005 + 0.003 * (cur - base_d)))
                return LinkCondition(cur, cur * 0.3, loss, min(0.95, 0.2 + cur / 100))
            return fn

        return ScenarioConfig(
            name="high_mobility",
            description="Random-walk rapid changes (low-altitude UAV)",
            num_links=num_links, max_steps=500,
            link_conditions=[make(10.0, 100), make(20.0, 200), make(30.0, 300)][:num_links],
            detection_sensitivity=0.7,
        )

    @classmethod
    def get_scenario(cls, name: str, **kwargs) -> ScenarioConfig:
        m = {
            "static_good": cls.static_good,
            "dynamic_fluctuation": cls.dynamic_fluctuation,
            "link_failure": cls.link_failure,
            "high_mobility": cls.high_mobility,
        }
        if name not in m:
            raise ValueError(f"Unknown: {name}. Available: {list(m.keys())}")
        return m[name](**kwargs)

    @classmethod
    def list_scenarios(cls) -> List[str]:
        return ["static_good", "dynamic_fluctuation", "link_failure", "high_mobility"]
