"""
INT 报告采集并写入链路状态数据库。
"""

import socket
import threading
import time
from typing import Callable, Dict, Optional

from .int_parser import IntParser, LinkMetricsCalculator, IntReport
from .path_state_db import PathStateDB


class INTCollector:
    """INTCollector 类。"""

    def __init__(self, path_db: PathStateDB,
                 listen_port: int = 50001,
                 buffer_size: int = 65536):
        self._db = path_db
        self._port = listen_port
        self._bufsize = buffer_size
        self._parser = IntParser()
        self._calc = LinkMetricsCalculator()
        self._socket: Optional[socket.socket] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._report_count = 0
        self._callbacks: list = []

    def start(self):
        if self._running:
            return
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind(("0.0.0.0", self._port))
        self._socket.settimeout(0.5)
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)
        if self._socket:
            self._socket.close()

    def register_callback(self, cb: Callable[[IntReport], None]):
        self._callbacks.append(cb)

    def _loop(self):
        while self._running:
            try:
                data, _ = self._socket.recvfrom(self._bufsize)
                self._process(data)
            except socket.timeout:
                continue
            except OSError:
                break

    def _process(self, data: bytes):
        report = self._parser.parse(data)
        if report is None:
            return
        self._report_count += 1

        # 中文注释。
        metrics: Dict[int, any] = self._calc.compute(report)
        for link_id, m in metrics.items():
            self._db.update(
                path_id=link_id,
                delay_us=m.delay_us,
                jitter_us=m.jitter_us,
                loss_rate=m.loss_rate,
                bw_bytes_per_s=m.bw_bytes_per_s,
                qdepth=m.qdepth,
                sent_delta=m.sent_delta,
                recv_delta=m.recv_delta,
            )

        for cb in self._callbacks:
            try:
                cb(report)
            except Exception:
                pass

    @property
    def stats(self) -> dict:
        return {"reports_received": self._report_count, "port": self._port}


class MockINTCollector(INTCollector):
    """
    MockINTCollector 类。
    """

    def __init__(self, path_db: PathStateDB, collection_interval_ms: int = 100):
        super().__init__(path_db)
        self._interval_ms = collection_interval_ms
        self._mock_running = False

    def start(self):
        self._mock_running = True

    def stop(self):
        self._mock_running = False

    def inject(self, link_id: int, delay_ms: float, jitter_ms: float,
               loss_rate: float, bw_util: float, qdepth: int = 0):
        """inject 函数。"""
        bw_bytes = bw_util * 1_250_000  # 中文注释。
        self._db.update(
            path_id=link_id,
            delay_us=delay_ms * 1000,
            jitter_us=jitter_ms * 1000,
            loss_rate=loss_rate,
            bw_bytes_per_s=bw_bytes,
            qdepth=qdepth,
        )
