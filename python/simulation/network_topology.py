"""
该模块实现项目中的一个功能组件。
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
import networkx as nx


@dataclass
class Host:
    """Host 类。"""
    name: str
    ip: str
    mac: str = "00:00:00:00:00:00"


@dataclass
class Switch:
    """Switch 类。"""
    name: str
    switch_id: int           # 中文注释。
    role: str = "transit"    # 中文注释。
    p4_json_path: str = ""
    grpc_address: str = ""
    device_id: int = 0


@dataclass
class LinkConfig:
    """LinkConfig 类。"""
    link_id: int
    bandwidth_mbps: float = 10.0
    delay_ms: float = 5.0
    jitter_ms: float = 2.0
    loss_rate: float = 0.001     # 中文注释。
    queue_size: int = 100
    description: str = ""


@dataclass
class TopologyConfig:
    """
    TopologyConfig 类。
    """
    name: str = "covert_2switch_3link"

    # 中文注释。
    sender: Host = field(default_factory=lambda: Host("h1", "10.0.1.1"))
    receiver: Host = field(default_factory=lambda: Host("h2", "10.0.1.2"))

    # 中文注释。
    s1: Switch = field(default_factory=lambda: Switch("s1", 1, "source"))
    s2: Switch = field(default_factory=lambda: Switch("s2", 2, "sink"))

    # 中文注释。
    links: List[LinkConfig] = field(default_factory=lambda: [
        LinkConfig(0, 10.0, 5.0,  2.0,  0.001, description="Link 0: good"),
        LinkConfig(1, 10.0, 15.0, 5.0,  0.005, description="Link 1: medium"),
        LinkConfig(2, 10.0, 30.0, 10.0, 0.010, description="Link 2: poor"),
    ])

    # 中文注释。
    graph: nx.DiGraph = field(default_factory=nx.DiGraph)

    @property
    def num_links(self) -> int:
        return len(self.links)

    def get_link(self, link_id: int) -> Optional[LinkConfig]:
        for link in self.links:
            if link.link_id == link_id:
                return link
        return None

    def update_link(self, link_id: int, **kwargs):
        """update_link 函数。"""
        for link in self.links:
            if link.link_id == link_id:
                for k, v in kwargs.items():
                    if hasattr(link, k):
                        setattr(link, k, v)
                break

    def build_graph(self):
        """build_graph 函数。"""
        self.graph = nx.DiGraph()
        # 中文注释。
        self.graph.add_edge("h1", "s1", link_id=-1, delay_ms=1, loss=0)
        # 中文注释。
        for link in self.links:
            self.graph.add_edge(
                "s1", "s2",
                link_id=link.link_id,
                delay_ms=link.delay_ms,
                jitter_ms=link.jitter_ms,
                loss_rate=link.loss_rate,
                bw_mbps=link.bandwidth_mbps,
            )
        # 中文注释。
        self.graph.add_edge("s2", "h2", link_id=-1, delay_ms=1, loss=0)


def default_topology() -> TopologyConfig:
    """default_topology 函数。"""
    topo = TopologyConfig()
    topo.build_graph()
    return topo
