"""
链路状态滑动窗口数据库。
"""

import time
from collections import deque
from dataclasses import dataclass
from typing import Dict, Optional
import numpy as np


@dataclass
class PathState:
    """单条链路的状态快照。"""
    path_id: int
    delay_ms: float = 0.0
    jitter_ms: float = 0.0
    loss_rate: float = 0.0
    bw_utilization: float = 0.0
    qdepth_avg: float = 0.0
    timestamp: float = 0.0
    sample_count: int = 0

    def to_vector(self) -> np.ndarray:
        return np.array([
            min(self.delay_ms / 200.0, 1.0),
            min(self.jitter_ms / 50.0, 1.0),
            self.loss_rate,
            self.bw_utilization,
        ], dtype=np.float32)


class SlidingWindow:
    """SlidingWindow 类。"""

    def __init__(self, window_ms: float = 500.0, max_samples: int = 100):
        self._window_ms = window_ms
        self._max = max_samples
        self._ts: deque = deque()
        self._delays: deque = deque()
        self._jitters: deque = deque()
        self._losses: deque = deque()
        self._bws: deque = deque()
        self._qdepths: deque = deque()

    def add(self, delay_us: float, jitter_us: float, loss_rate: float,
            bw_bytes_per_s: float, qdepth: int):
        now = time.time()
        self._ts.append(now)
        self._delays.append(delay_us / 1000.0)     # 中文注释。
        self._jitters.append(jitter_us / 1000.0)
        self._losses.append(loss_rate)
        self._bws.append(bw_bytes_per_s)
        self._qdepths.append(qdepth)
        self._prune(now)

    def compute(self) -> Optional[PathState]:
        if not self._delays:
            return None
        delays = np.array(self._delays)
        return PathState(
            path_id=-1,
            delay_ms=float(np.mean(delays)),
            jitter_ms=float(np.std(delays)) if len(delays) > 1 else 0.0,
            loss_rate=float(np.mean(self._losses)),
            bw_utilization=min(1.0, float(np.mean(self._bws)) / 1_250_000),
            qdepth_avg=float(np.mean(self._qdepths)) if self._qdepths else 0.0,
            timestamp=time.time(),
            sample_count=len(self._delays),
        )

    def _prune(self, now: float):
        cutoff = now - self._window_ms / 1000.0
        for seq in [self._ts, self._delays, self._jitters,
                     self._losses, self._bws, self._qdepths]:
            while seq and self._ts and self._ts[0] < cutoff:
                seq.popleft()
            while len(seq) > self._max:
                seq.popleft()


class PathStateDB:
    """PathStateDB 类。"""

    def __init__(self, num_paths: int = 3, window_size_ms: float = 500.0):
        self._num = num_paths
        self._windows = {i: SlidingWindow(window_size_ms) for i in range(num_paths)}

    def update(self, path_id: int, delay_us: float, jitter_us: float,
               loss_rate: float, bw_bytes_per_s: float, qdepth: int = 0):
        if path_id in self._windows:
            self._windows[path_id].add(
                delay_us, jitter_us, loss_rate, bw_bytes_per_s, qdepth)

    def get_path_state(self, path_id: int) -> Optional[PathState]:
        if path_id in self._windows:
            state = self._windows[path_id].compute()
            if state:
                state.path_id = path_id
            return state
        return None

    def get_all_states(self) -> Dict[int, PathState]:
        return {i: s for i in range(self._num)
                if (s := self.get_path_state(i)) is not None}

    def get_state_vector(self) -> np.ndarray:
        vec = np.zeros(self._num * 4, dtype=np.float32)
        for i in range(self._num):
            s = self.get_path_state(i)
            if s:
                base = i * 4
                vec[base:base+4] = s.to_vector()
        return vec

    def reset(self):
        for w in self._windows.values():
            w.__init__()

    @property
    def num_paths(self) -> int:
        return self._num
