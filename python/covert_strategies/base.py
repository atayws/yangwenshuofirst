"""
隐蔽信道策略的公共数据结构和抽象接口。
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Tuple, Any


class StrategyID(IntEnum):
    """隐蔽策略编号，和包内 strategy_id 保持一致。"""
    TIMING_HIGH_COVERT = 0
    TIMING_HIGH_CAPACITY = 1
    PROTOCOL_HIGH_RELIABILITY = 2
    STATISTICAL_FUSION = 3
    FULL_PATH_REDUNDANCY = 4
    PATH_SEQUENCE = 5


@dataclass
class PacketSpec:
    """
    单个隐蔽数据包的发送描述。
    """
    payload: bytes                                    # 实际发送的业务载荷。
    sequence_num: int = 0                             # 本次隐蔽消息的序号。
    fragment_id: int = 0                              # 当前承载包在消息中的片段编号。
    total_fragments: int = 1                          # 本次隐蔽消息总承载包数。
    is_redundant: bool = False                        # 是否为冗余或校验承载包。
    # 可选的协议字段、长度和时序控制信息。
    ip_id_field: Optional[int] = None                 # 需要写入 IPv4 Identification 的值。
    target_packet_length: Optional[int] = None        # 期望发送出的 IP 包长度。
    send_delay_ms: float = 0.0                        # 相对前一个包的发送间隔。
    covert_nonce: int = 0                             # 字段加密或认证使用的随机/序号输入。

    path_id: int = 0                                  # 期望使用的路径编号。
    strategy_id: int = 0                              # 该承载包所属策略编号。


@dataclass
class StrategyMetrics:
    """
    隐蔽策略在当前网络状态下的性能估计。
    """
    covertness_score: float = 0.0      
    capacity_bps: float = 0.0          
    reliability_score: float = 0.0     
    delay_tolerance_ms: float = 0.0    
    loss_tolerance: float = 0.0        

    def to_dict(self) -> dict:
        return {
            "covertness_score": round(self.covertness_score, 3),
            "capacity_bps": round(self.capacity_bps, 1),
            "reliability_score": round(self.reliability_score, 3),
            "delay_tolerance_ms": round(self.delay_tolerance_ms, 1),
            "loss_tolerance": round(self.loss_tolerance, 3),
        }


@dataclass
class PathState:
    """单条链路的状态快照。"""
    path_id: int
    delay_ms: float
    jitter_ms: float
    loss_rate: float       # 当前链路丢包率。
    bw_utilization: float   # 当前链路带宽利用率。
    timestamp: float = 0.0


class CovertStrategy(ABC):
    """
    所有隐蔽信道策略的抽象基类。
    """
    # 子类需要声明自己的策略编号和可读名称。
    strategy_id: StrategyID
    name: str = "base"
    description: str = ""

    def __init__(self, config: Optional[dict] = None):
        """
        __init__ 函数。
        """
        self._config = config or {}
        self._bytes_encoded: int = 0
        self._bytes_decoded: int = 0

    @abstractmethod
    def encode(
        self, data: bytes, path_id: int, seq_num: int = 0
    ) -> List[PacketSpec]:
        """
        编码数据并生成待发送的数据包描述。
        """
        ...

    @abstractmethod
    def decode(
        self,
        packets: List[bytes],
        metadata: Optional[List[dict]] = None,
    ) -> Optional[bytes]:
        """
        根据收到的数据包和元数据恢复原始隐蔽数据。
        """
        ...

    @abstractmethod
    def get_metrics(self, network_state: PathState) -> StrategyMetrics:
        """
        估计当前网络状态下该策略的性能指标。
        """
        ...

    def configure(self, **kwargs):
        """configure 函数。"""
        self._config.update(kwargs)

    @property
    def stats(self) -> dict:
        """stats 函数。"""
        return {
            "strategy_id": int(self.strategy_id),
            "name": self.name,
            "bytes_encoded": self._bytes_encoded,
            "bytes_decoded": self._bytes_decoded,
        }

    def __repr__(self) -> str:
        return f"<{self.name}(id={int(self.strategy_id)})>"
