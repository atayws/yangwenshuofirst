"""
用于 PPO 训练的多路径隐蔽传输 Gymnasium 仿真环境。
"""

from typing import Optional, Tuple, Any, Dict, List
import numpy as np
import gymnasium as gym
from gymnasium import spaces

from .link_emulator import LinkEmulator
from .scenario_loader import ScenarioLibrary, ScenarioConfig
from ..covert_strategies.base import StrategyID
from ..covert_strategies.strategy_registry import get_strategy
from ..rl_agent.reward_calculator import RewardCalculator, TransmissionFeedback


class CovertMultiPathEnv(gym.Env):
    """多路径隐蔽传输强化学习环境。"""

    metadata = {"render_modes": ["human", "none"]}

    def __init__(
        self,
        num_links: int = 3,
        num_paths: Optional[int] = None,
        scenario: str = "static_good",
        max_steps: int = 500,
        message_size_bytes: int = 16,
        target_throughput_bps: float = 100.0,
    ):
        super().__init__()
        if num_paths is not None:
            num_links = num_paths
        self.num_links = num_links
        self._scenario_name = scenario
        self._max_steps_override = max_steps
        self.message_size_bytes = message_size_bytes
        self.target_throughput_bps = target_throughput_bps

        self.observation_space = spaces.Box(
            low=0.0, high=1.0, shape=(num_links * 4,), dtype=np.float32)
        self.action_space = spaces.MultiDiscrete([5] * num_links)

        # 中文注释。
        self._scenario: Optional[ScenarioConfig] = None
        self._link_emu: Optional[LinkEmulator] = None
        self._strategies: Dict[int, Any] = {}
        self._reward_calc = RewardCalculator()
        self._current_step = 0
        self._episode_history: List[dict] = []

        self._load_strategies()

    def _load_strategies(self):
        for sid in range(5):
            try:
                self._strategies[sid] = get_strategy(StrategyID(sid))
            except Exception:
                pass

    def reset(self, *, seed=None, options=None) -> Tuple[np.ndarray, dict]:
        super().reset(seed=seed)
        name = options.get("scenario", self._scenario_name) if options else self._scenario_name
        self._scenario = ScenarioLibrary.get_scenario(name, num_links=self.num_links)
        self._link_emu = LinkEmulator(num_links=self.num_links, seed=seed)
        self._current_step = 0
        self._episode_history.clear()
        self._reward_calc.reset()
        self._apply_conditions()
        return self._get_obs(), {"scenario": name}

    def step(self, action: np.ndarray) -> Tuple[np.ndarray, float, bool, bool, dict]:
        self._current_step += 1
        action = np.clip(np.array(action, dtype=np.int32).flatten(), 0, 4)

        # 中文注释。
        message = np.random.bytes(self.message_size_bytes)
        tx_data = {}
        for link_id in range(self.num_links):
            strat = self._strategies.get(int(action[link_id]))
            if strat is None:
                continue
            try:
                packets = strat.encode(message, path_id=link_id, seq_num=self._current_step)
            except Exception:
                packets = []
            results = []
            for pkt in packets:
                r = self._link_emu.transmit(link_id, len(pkt.payload))
                results.append({
                    "success": r.success, "delay_ms": r.delay_ms,
                    "payload": pkt.payload, "ip_id": pkt.ip_id_field,
                    "nonce": pkt.covert_nonce,
                    "arrival_time_ms": self._current_step * 100 + r.delay_ms,
                })
            tx_data[link_id] = results

        # 中文注释。
        delivered, attempted = 0, len(message)
        packets_sent = sum(len(results) for results in tx_data.values())
        packets_delivered = sum(
            1 for results in tx_data.values() for r in results if r["success"]
        )
        for link_id, results in tx_data.items():
            strat = self._strategies.get(int(action[link_id]))
            if strat is None or not results:
                continue
            payloads = [r["payload"] for r in results if r["success"]]
            meta = [{"arrival_time_ms": r["arrival_time_ms"], "ip_id": r["ip_id"],
                     "nonce": r.get("nonce", i)}
                    for i, r in enumerate(results) if r["success"]]
            if payloads:
                try:
                    decoded = strat.decode(payloads, meta)
                    if decoded:
                        delivered += len(decoded)
                except Exception:
                    pass

        # 中文注释。
        delivered_unique = min(delivered, attempted)
        detected = self._check_detection(tx_data, action)
        throughput = delivered_unique * 8 / 0.1  # 中文注释。
        feedback = TransmissionFeedback(
            detected=detected,
            success_ratio=delivered_unique / max(attempted, 1),
            bytes_delivered=delivered_unique,
            bytes_total=attempted,
            throughput_bps=throughput,
            target_throughput_bps=self.target_throughput_bps,
        )
        reward = self._reward_calc.compute(feedback, action)

        # 中文注释。
        self._apply_conditions()
        obs = self._get_obs()
        max_s = self._max_steps_override or self._scenario.max_steps
        done = self._current_step >= max_s

        info = {
            "reward": reward, "throughput_bps": throughput,
            "success_ratio": feedback.success_ratio,
            "bytes_sent": attempted,
            "bytes_delivered": delivered_unique,
            "packets_sent": packets_sent,
            "packets_delivered": packets_delivered,
            "detected": detected, "strategies_used": action.tolist(),
            "path_delay_ms": self._path_feature_dict("delay_ms"),
            "path_jitter_ms": self._path_feature_dict("jitter_ms"),
            "path_loss_rate": self._path_feature_dict("loss_rate"),
        }
        self._episode_history.append(info)

        return obs, reward, done, False, info

    def _apply_conditions(self):
        for lid in range(self.num_links):
            c = self._scenario.link_conditions[lid](self._current_step)
            self._link_emu.set_link(lid, delay_ms=c.delay_ms,
                jitter_ms=c.jitter_ms, loss_rate=c.loss_rate,
                bw_mbps=10.0 * (1.0 - c.bw_utilization))

    def _get_obs(self) -> np.ndarray:
        """_get_obs 函数。"""
        obs = np.zeros(self.num_links * 4, dtype=np.float32)
        for lid in range(self.num_links):
            s = self._link_emu.get_link_state(lid)
            base = lid * 4
            obs[base + 0] = np.clip(s.delay_ms / 200.0, 0, 1)
            obs[base + 1] = np.clip(s.jitter_ms / 50.0, 0, 1)
            obs[base + 2] = np.clip(s.loss_rate, 0, 1)
            obs[base + 3] = np.clip(1.0 - s.bw_mbps / 10.0, 0, 1)
        return obs.astype(np.float32)

    def _path_feature_dict(self, attr: str) -> Dict[int, float]:
        values = {}
        for lid in range(self.num_links):
            s = self._link_emu.get_link_state(lid)
            values[lid] = float(getattr(s, attr))
        return values

    def _check_detection(self, tx_data: dict, strategies: np.ndarray) -> bool:
        score = 0.0
        for lid in range(self.num_links):
            sid = int(strategies[lid])
            scores = {0: 0.05, 1: 0.15, 2: 0.12, 3: 0.10, 4: 0.08}
            score += scores.get(sid, 0.10) * self._scenario.detection_sensitivity
        return (score / self.num_links + np.random.normal(0, 0.1)) > 0.7

    def get_episode_stats(self) -> dict:
        """get_episode_stats 函数。"""
        if not self._episode_history:
            return {}

        rewards = [m["reward"] for m in self._episode_history]
        throughputs = [m["throughput_bps"] for m in self._episode_history]
        success = [m["success_ratio"] for m in self._episode_history]
        detections = [1.0 if m["detected"] else 0.0 for m in self._episode_history]

        counts = np.zeros(5, dtype=int)
        for m in self._episode_history:
            for sid in m["strategies_used"]:
                if 0 <= sid < 5:
                    counts[sid] += 1
        total = counts.sum()
        distribution = {
            int(i): float(counts[i] / total)
            for i in range(5)
            if total > 0 and counts[i] > 0
        }

        return {
            "steps": len(self._episode_history),
            "mean_reward": float(np.mean(rewards)),
            "total_reward": float(np.sum(rewards)),
            "mean_throughput": float(np.mean(throughputs)),
            "mean_success_ratio": float(np.mean(success)),
            "detection_rate": float(np.mean(detections)),
            "strategy_distribution": distribution,
        }

    def render(self): pass
    def close(self): pass
