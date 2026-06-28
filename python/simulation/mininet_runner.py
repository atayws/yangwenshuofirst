"""
该模块实现项目中的一个功能组件。
"""

import os
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class MininetLinkConfig:
    src: str
    dst: str
    bw_mbps: float = 10.0
    delay_ms: float = 5.0
    jitter_ms: float = 2.0
    loss_percent: float = 0.0


@dataclass
class MininetConfig:
    topology_name: str = "covert_2switch_3link"
    p4_json_path: str = ""
    switches: List[str] = field(default_factory=lambda: ["s1", "s2"])
    hosts: List[Tuple[str, str]] = field(default_factory=lambda: [
        ("h1", "10.0.1.1/24"), ("h2", "10.0.1.2/24")
    ])
    links: List[MininetLinkConfig] = field(default_factory=list)


class MininetRunner:
    """MininetRunner 类。"""

    def __init__(self, config: MininetConfig):
        self._config = config
        self._net = None
        self._running = False

    def build_network(self):
        self._check_deps()
        try:
            from mininet.net import Mininet
            from mininet.topo import Topo
            from mininet.link import TCLink

            topo = Topo()
            for name, ip in self._config.hosts:
                topo.addHost(name, ip=ip)
            for sw in self._config.switches:
                topo.addSwitch(sw)
            for link in self._config.links:
                topo.addLink(link.src, link.dst, bw=link.bw_mbps,
                             delay=f"{link.delay_ms}ms", loss=link.loss_percent)

            self._net = Mininet(topo=topo, link=TCLink)
            self._net.start()
            self._running = True
            print(f"[MininetRunner] {self._config.topology_name} started")
        except ImportError as e:
            raise RuntimeError(f"Mininet not available: {e}")

    def stop(self):
        if self._net:
            self._net.stop()
            self._running = False

    @staticmethod
    def _check_deps():
        try:
            import mininet  # noqa: F401
        except ImportError:
            raise RuntimeError("Mininet required. Use CovertMultiPathEnv for offline.")


def build_3link_config(p4_json: str) -> MininetConfig:
    """build_3link_config 函数。"""
    return MininetConfig(
        p4_json_path=p4_json,
        links=[
            MininetLinkConfig("s1", "s2", 10, 5.0,  2.0,  0.1),
            MininetLinkConfig("s1", "s2", 10, 15.0, 5.0,  0.5),
            MininetLinkConfig("s1", "s2", 10, 30.0, 10.0, 1.0),
        ] + [
            MininetLinkConfig("h1", "s1", 100, 1, 0, 0),
            MininetLinkConfig("s2", "h2", 100, 1, 0, 0),
        ]
    )
