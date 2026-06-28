"""
P4 交换机配置管理和离线模拟连接。
"""

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class SwitchConfig:
    """SwitchConfig 类。"""
    name: str
    switch_id: int
    grpc_address: str = "127.0.0.1:50051"
    device_id: int = 0
    p4_json_path: str = ""
    p4_info_path: str = ""


@dataclass
class RouteEntry:
    """RouteEntry 类。"""
    dst_ip: str
    prefix_len: int
    egress_port: int


class SwitchManager:
    """
    SwitchManager 类。
    """

    def __init__(self):
        self._connections: Dict[str, "MockP4Connection"] = {}
        self._strategy_assignments: Dict[int, int] = {}

    def connect(self, config: SwitchConfig) -> bool:
        try:
            conn = MockP4Connection(config)
            self._connections[config.name] = conn
            return True
        except Exception:
            return False

    def disconnect(self, name: str = None):
        if name:
            self._connections.pop(name, None)
        else:
            self._connections.clear()

    def set_routing(self, switch_name: str, entries: List[RouteEntry]):
        conn = self._connections.get(switch_name)
        if conn:
            for e in entries:
                conn.write_table("ipv4_lpm", {"dstAddr": (e.dst_ip, e.prefix_len)},
                                "set_egress", {"port": e.egress_port})

    def configure_int(
        self,
        switch_name: str,
        switch_id: int,
        enabled: bool = True,
        interval_us: int = 100_000,
        terminal: bool = False,
    ):
        conn = self._connections.get(switch_name)
        if conn:
            conn.write_register("reg_int_enabled", 0, 1 if enabled else 0)
            conn.write_register("reg_switch_id", 0, switch_id)
            conn.write_register("reg_int_interval_us", 0, interval_us)
            conn.write_register("reg_next_sample_time", 0, 0)
            conn.write_register("reg_int_terminal_swid", 0, switch_id if terminal else 0)

    def set_link_strategy(self, link_id: int, strategy_id: int):
        """记录控制面选择的链路策略，实际隐蔽编解码由终端侧 Python 执行。"""
        self._strategy_assignments[link_id] = strategy_id

    def set_path_to_port(self, switch_name: str, path_id: int, port: int):
        conn = self._connections.get(switch_name)
        if conn:
            conn.write_table("path_to_port", {"path_id": path_id},
                            "route_by_path", {"path_id": path_id, "port_0": port,
                                              "port_1": port, "port_2": port})

    def set_int_terminal(self, switch_name: str, port: int):
        conn = self._connections.get(switch_name)
        if conn:
            conn.write_table("int_terminal", {"egress_spec": port},
                            "generate_int_report", {})

    @property
    def connections(self):
        return list(self._connections.keys())

    @property
    def strategy_assignments(self):
        return self._strategy_assignments.copy()


class MockP4Connection:
    """MockP4Connection 类。"""

    def __init__(self, config: SwitchConfig):
        self.config = config
        self._tables: Dict[str, Dict] = {}
        self._registers: Dict[str, Dict[int, int]] = {}

    def write_table(self, table: str, match: dict, action: str, params: dict):
        key = f"{table}:{sorted(match.items())}"
        self._tables[key] = {"table": table, "match": match,
                             "action": action, "params": params}

    def write_register(self, name: str, index: int, value: int):
        if name not in self._registers:
            self._registers[name] = {}
        self._registers[name][index] = value

    def read_register(self, name: str, index: int) -> int:
        return self._registers.get(name, {}).get(index, 0)

    def close(self): pass
