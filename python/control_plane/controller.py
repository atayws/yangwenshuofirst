"""
控制器主循环，连接 INT、状态库、PPO 和交换机配置。
"""

import asyncio
import time
from typing import Dict, Optional
import numpy as np

from .path_state_db import PathStateDB, PathState
from .int_collector import INTCollector, MockINTCollector
from .switch_manager import SwitchManager, SwitchConfig
from ..utils.config import load_config
from ..utils.logger import get_logger


class Controller:
    """Controller 类。"""

    def __init__(self, config_path: str = None):
        cfg = load_config(config_path) if config_path else load_config("experiments/configs/default.yaml")
        self._cfg = cfg
        self._num_links = cfg.get("network.num_links", 3)
        self._decision_interval_ms = cfg.get("int.collection_interval_ms", 100)

        self._path_db = PathStateDB(num_paths=self._num_links)
        self._int_collector: Optional[INTCollector] = None
        self._switch_mgr = SwitchManager()
        self._rl_agent = None
        self._assignments: Dict[int, int] = {}
        self._running = False
        self._step = 0
        self._logger = get_logger()

    async def initialize(self, use_mock: bool = True):
        if use_mock:
            self._int_collector = MockINTCollector(
                path_db=self._path_db,
                collection_interval_ms=self._decision_interval_ms)
        else:
            self._int_collector = INTCollector(
                path_db=self._path_db,
                collection_interval_ms=self._decision_interval_ms)
        self._int_collector.start()

        from ..rl_agent.ppo_agent import PPOAgent
        rl_cfg = self._cfg.get("rl", {})
        self._rl_agent = PPOAgent(
            num_paths=self._num_links,
            state_dim=self._num_links * 4,
            config=rl_cfg)

        model_path = self._cfg.get("rl.model_path", None)
        if model_path:
            try:
                self._rl_agent.load(model_path)
            except FileNotFoundError:
                pass

        self._logger.info(f"Controller: {self._num_links} links, {self._decision_interval_ms}ms interval")

    async def run(self, max_steps: int = None, training: bool = False):
        self._running = True
        while self._running:
            state_vec = self._path_db.get_state_vector()
            action, _, _ = self._rl_agent.select_action(state_vec)

            assignments = {}
            for lid in range(self._num_links):
                sid = int(action[lid]) if lid < len(action) else 0
                assignments[lid] = sid
                self._switch_mgr.set_link_strategy(lid, sid)

            self._assignments = assignments
            self._step += 1

            if training and self._rl_agent.buffer.size >= self._rl_agent.batch_size:
                self._rl_agent.update()

            if max_steps and self._step >= max_steps:
                break

            await asyncio.sleep(self._decision_interval_ms / 1000.0)

    def stop(self):
        self._running = False
        if self._int_collector:
            self._int_collector.stop()

    def get_assignments(self) -> Dict[int, int]:
        return self._assignments.copy()

    @property
    def path_db(self) -> PathStateDB:
        return self._path_db

    @property
    def rl_agent(self):
        return self._rl_agent

    @property
    def step_count(self) -> int:
        return self._step
