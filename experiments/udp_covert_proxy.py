#!/usr/bin/env python3
"""
UDP 业务流隐蔽代理。

这个脚本把真实 UDP 业务流作为隐蔽策略的承载层：
- 发送端应用先把 UDP 业务包发给本机代理，例如 iperf -u 发到 127.0.0.1:6000；
- 发送端代理从策略库取出 PacketSpec，把策略字段叠加到这些真实业务包上；
- 接收端代理抓取代理间 UDP 包，解析隐蔽字段，再把原始业务载荷转发给本机业务服务端；
- P4 交换机只负责转发、多路径调度和 INT，不解析隐蔽数据。

当前支持策略 0~5：
- 策略0/1：在业务 UDP payload 前加入 2 字节同步标签，并控制包间隔；
- 策略2：把可靠分块编码写入 IPv4 ID，业务 payload 不改动；
- 策略3：在业务 payload 前加入包长同步小头，通过 IP 包长区间承载数据；
- 策略4：把喷泉码符号写入 IPv4 ID，业务 payload 不改动；
- 策略5：把路径序列自描述字段写入 IPv4 ID，业务 payload 不改动。
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from python.covert_strategies.base import PacketSpec, StrategyID
from python.covert_strategies.strategy_registry import get_strategy
from python.covert_strategies.timing_sync_tag import ANCHOR_PHASE, parse_timing_tag
from python.receiver.strategy_router import StrategyReceiverRouter


TIMING_STRATEGIES = {0, 1}
IP_ID_STRATEGIES = {2, 4, 5}
STRATEGY3_HEADER_LEN = 12
STRATEGY3_PROXY_LEN_BYTES = 2
IP_UDP_HEADER_BYTES = 28


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="UDP 业务流隐蔽代理")
    subparsers = parser.add_subparsers(dest="mode", required=True)

    sender = subparsers.add_parser("sender", help="发送端代理：本机业务流 -> 网络业务流")
    sender.add_argument("--strategy", type=int, required=True, choices=range(6))
    sender.add_argument("--hidden-input", required=True, help="待隐蔽传输的数据文件")
    sender.add_argument("--listen-ip", default="127.0.0.1")
    sender.add_argument("--listen-port", type=int, default=6000)
    sender.add_argument("--remote-ip", required=True)
    sender.add_argument("--remote-port", type=int, default=6100)
    sender.add_argument("--src-ip", default=None)
    sender.add_argument("--sport", type=int, default=0, help="0 表示沿用本地业务源端口")
    sender.add_argument("--iface", default=None, help="scapy-l2 模式使用的出接口")
    sender.add_argument("--src-mac", default=None)
    sender.add_argument("--dst-mac", default="00:00:00:00:00:02")
    sender.add_argument("--send-mode", choices=["auto", "socket", "scapy-l2"], default="auto")
    sender.add_argument("--path-id", type=int, default=0)
    sender.add_argument("--path-weights", default="1,1,1")
    sender.add_argument("--seq-num", type=int, default=1)
    sender.add_argument("--sync-key", type=lambda x: int(x, 0), default=0x5A17)
    sender.add_argument("--socket-buffer", type=int, default=4 * 1024 * 1024)
    sender.add_argument("--max-idle", type=float, default=3.0, help="业务流停止后等待多少秒退出")
    sender.add_argument("--business-payload-len", type=int, default=32)
    sender.add_argument(
        "--timing-repeat",
        type=int,
        default=3,
        help="策略0/1每个时序承载包重复挂载多少个业务包，用于抵抗轻微丢包",
    )
    sender.add_argument(
        "--path-sequence-repeat",
        type=int,
        default=3,
        help="策略5每个路径序列承载包重复挂载多少个业务包，用于抵抗轻微丢包",
    )
    sender.add_argument(
        "--strategy3-business-budget",
        type=int,
        default=220,
        help="策略3默认按多大的原始业务 payload 规划包长区间",
    )
    sender.add_argument(
        "--drop-tagged-every",
        type=int,
        default=0,
        help="测试用：每 N 个隐蔽承载包丢弃 1 个，0 表示不主动丢弃",
    )
    sender.add_argument("--summary", default="experiments/results/udp_proxy_sender_summary.json")

    receiver = subparsers.add_parser("receiver", help="接收端代理：网络业务流 -> 本机业务流")
    receiver.add_argument("--strategy", type=int, required=True, choices=range(6))
    receiver.add_argument("--listen-ip", default="0.0.0.0")
    receiver.add_argument("--listen-port", type=int, default=6100)
    receiver.add_argument("--iface", default=None, help="抓取代理间业务包的接口，例如 h2-eth0")
    receiver.add_argument("--receive-mode", choices=["auto", "socket", "sniff"], default="auto")
    receiver.add_argument("--forward-ip", default="127.0.0.1")
    receiver.add_argument("--forward-port", type=int, default=5201)
    receiver.add_argument("--expected-bytes", type=int, default=None)
    receiver.add_argument("--seq-num", type=int, default=1)
    receiver.add_argument("--sync-key", type=lambda x: int(x, 0), default=0x5A17)
    receiver.add_argument("--timeout", type=float, default=30.0)
    receiver.add_argument("--max-idle", type=float, default=3.0)
    receiver.add_argument("--business-payload-len", type=int, default=32)
    receiver.add_argument("--timing-repeat", type=int, default=3)
    receiver.add_argument("--path-sequence-repeat", type=int, default=3)
    receiver.add_argument("--strategy3-business-budget", type=int, default=220)
    receiver.add_argument("--hidden-output", default="experiments/results/udp_proxy_hidden_output.bin")
    receiver.add_argument("--summary", default="experiments/results/udp_proxy_receiver_summary.json")

    plan_sender = subparsers.add_parser("plan-sender", help="发送端计划代理：持续业务流 -> 多策略隐蔽承载")
    plan_sender.add_argument("--plan-file", required=True, help="多段策略计划 JSON")
    plan_sender.add_argument("--listen-ip", default="127.0.0.1")
    plan_sender.add_argument("--listen-port", type=int, default=6000)
    plan_sender.add_argument("--remote-ip", required=True)
    plan_sender.add_argument("--src-ip", default=None)
    plan_sender.add_argument("--iface", required=True)
    plan_sender.add_argument("--src-mac", default=None)
    plan_sender.add_argument("--dst-mac", default="00:00:00:00:00:02")
    plan_sender.add_argument("--sport", type=int, default=0, help="0 表示沿用本地业务源端口")
    plan_sender.add_argument("--plain-remote-port", type=int, default=6200)
    plan_sender.add_argument("--control-dir", default=None, help="可选：逐段等待控制面确认路径已切换")
    plan_sender.add_argument("--sync-key", type=lambda x: int(x, 0), default=0x5A17)
    plan_sender.add_argument("--socket-buffer", type=int, default=4 * 1024 * 1024)
    plan_sender.add_argument("--max-idle", type=float, default=5.0)
    plan_sender.add_argument("--timing-repeat", type=int, default=2)
    plan_sender.add_argument("--path-sequence-repeat", type=int, default=2)
    plan_sender.add_argument("--strategy3-business-budget", type=int, default=260)
    plan_sender.add_argument(
        "--l2-send-gap-ms",
        type=float,
        default=1.0,
        help="scapy-l2 连续发包的最小间隔，避免 BMv2 或抓包接收端被瞬时突发压爆。",
    )
    plan_sender.add_argument("--summary", default="experiments/results/udp_proxy_plan_sender_summary.json")

    plan_receiver = subparsers.add_parser("plan-receiver", help="接收端计划代理：多策略识别 -> 业务流转发")
    plan_receiver.add_argument("--plan-file", required=True, help="多段策略计划 JSON")
    plan_receiver.add_argument("--listen-ip", default="0.0.0.0")
    plan_receiver.add_argument("--iface", required=True)
    plan_receiver.add_argument("--forward-ip", default="127.0.0.1")
    plan_receiver.add_argument("--forward-port", type=int, default=5201)
    plan_receiver.add_argument("--sync-key", type=lambda x: int(x, 0), default=0x5A17)
    plan_receiver.add_argument("--timeout", type=float, default=90.0)
    plan_receiver.add_argument("--max-idle", type=float, default=6.0)
    plan_receiver.add_argument("--hidden-output", default="experiments/results/udp_proxy_plan_hidden_output.bin")
    plan_receiver.add_argument("--summary", default="experiments/results/udp_proxy_plan_receiver_summary.json")

    return parser.parse_args()


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def parse_path_weights(raw: str) -> List[int]:
    values = [int(item.strip()) for item in str(raw).split(",") if item.strip()]
    values = values[:3]
    while len(values) < 3:
        values.append(0)
    if sum(values) <= 0:
        return [1, 1, 1]
    return [max(0, item) for item in values]


def load_proxy_plan(path: str) -> dict:
    """读取真实业务流代理使用的多策略计划文件。"""

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    segments = data.get("segments", [])
    if not segments:
        raise ValueError("plan-file 中必须包含 segments")
    for index, segment in enumerate(segments):
        strategy_id = int(segment["strategy_id"])
        if strategy_id < 0 or strategy_id > 5:
            raise ValueError(f"segment {index}: strategy_id 只能是 0~5")
        if strategy_id == 4 and len(segment.get("paths", [])) < 2:
            raise ValueError(f"segment {index}: 策略4必须绑定至少两条路径")
        segment.setdefault("segment_id", index)
        segment.setdefault("sequence_num", 1 + index)
        segment.setdefault("remote_port", 6100 + index)
        segment.setdefault("paths", [0])
    return data


def load_proxy_segment(path: str, segment_id: int) -> Tuple[dict, dict]:
    """重新读取计划文件中的单个分段，用于 chunk 级动态重规划。"""

    plan = load_proxy_plan(path)
    for segment in plan["segments"]:
        if int(segment.get("segment_id", -1)) == int(segment_id):
            return plan, dict(segment)
    raise ValueError(f"plan-file 中找不到 segment {segment_id}")


def namespace_for_strategy(
    strategy_id: int,
    sync_key: int,
    expected_bytes: Optional[int],
    strategy3_budget: int = 260,
    path_weights: str = "1,1,1",
) -> argparse.Namespace:
    """构造 build_strategy_config 所需的轻量参数对象。"""

    return argparse.Namespace(
        strategy=int(strategy_id),
        sync_key=int(sync_key),
        expected_bytes=expected_bytes,
        business_payload_len=32,
        strategy3_business_budget=int(strategy3_budget),
        path_weights=path_weights,
    )


def segment_path_weights(segment: dict) -> str:
    """把计划中的路径集合转换成策略4使用的三路权重字符串。"""

    weights = [0, 0, 0]
    for path in segment.get("paths", []):
        path_id = int(path)
        if 0 <= path_id <= 2:
            weights[path_id] = int(segment.get("weight", 1)) or 1
    if sum(weights) <= 0:
        weights = [1, 1, 1]
    return ",".join(str(item) for item in weights)


def strategy_config_for_segment(segment: dict, sync_key: int) -> Dict[str, object]:
    """为计划中的单个分段生成策略配置。"""

    strategy_id = int(segment["strategy_id"])
    expected_bytes = int(segment.get("expected_bytes", len(segment.get("hidden_hex", "")) // 2))
    ns = namespace_for_strategy(
        strategy_id=strategy_id,
        sync_key=sync_key,
        expected_bytes=expected_bytes,
        strategy3_budget=int(segment.get("strategy3_business_budget", 260)),
        path_weights=segment_path_weights(segment),
    )
    config = build_strategy_config(ns, expected_bytes)
    for key, value in segment.get("strategy_config", {}).items():
        config[key] = value
    return config


def encode_plan_segment(segment: dict, sync_key: int) -> Tuple[List[PacketSpec], Dict[str, object]]:
    """把计划分段中的隐蔽数据编码成 PacketSpec 列表。"""

    strategy_id = int(segment["strategy_id"])
    hidden = bytes.fromhex(str(segment.get("hidden_hex", "")))
    config = strategy_config_for_segment(segment, sync_key)
    strategy = get_strategy(StrategyID(strategy_id), config=config)
    packets = strategy.encode(
        hidden,
        path_id=int(segment.get("paths", [0])[0]),
        seq_num=int(segment.get("sequence_num", 1)),
    )
    return packets, config


def strategy3_length_bands(business_budget: int) -> List[Tuple[int, int]]:
    """
    按原始业务 payload 预算生成策略3包长区间。

    这里的长度是 IPv4 totalLen。策略3需要能够在业务载荷前加入 12 字节同步小头
    和 2 字节原始载荷长度，因此业务包太大时必须降低 iperf -l 或增大 MTU。
    """

    min_ip_len = IP_UDP_HEADER_BYTES + STRATEGY3_HEADER_LEN + STRATEGY3_PROXY_LEN_BYTES
    min_ip_len += max(0, int(business_budget))
    first_low = max(260, min_ip_len + 8)
    bands = []
    width = 90
    gap = 120
    for index in range(4):
        low = first_low + index * (width + gap)
        bands.append((low, low + width))
    return bands


def build_strategy_config(args: argparse.Namespace, hidden_len: Optional[int]) -> Dict[str, object]:
    """生成发送端和接收端需要保持一致的策略参数。"""

    strategy_id = int(args.strategy)
    config: Dict[str, object] = {
        "sync_key": int(args.sync_key),
        "business_payload_len": int(args.business_payload_len),
    }
    if hidden_len is not None:
        config["expected_bytes"] = int(hidden_len)
    elif getattr(args, "expected_bytes", None) is not None:
        config["expected_bytes"] = int(args.expected_bytes)

    if strategy_id == 0:
        config.update(
            {
                "short_gap_ms": 10,
                "long_gap_ms": 24,
                "min_relation_delta_ms": 5,
                "max_jitter_tolerance_ms": 8,
            }
        )
    elif strategy_id == 1:
        config.update(
            {
                "rank_gaps_ms": [12, 26, 48],
                "min_rank_delta_ms": 7,
                "max_jitter_tolerance_ms": 10,
            }
        )
    elif strategy_id == 3:
        config.update(
            {
                "header_overhead_bytes": IP_UDP_HEADER_BYTES,
                "length_bands": strategy3_length_bands(int(args.strategy3_business_budget)),
                "classification_margin_bytes": 70,
            }
        )
    elif strategy_id == 4:
        config.update(
            {
                "k": 8,
                "num_output": 16,
                "path_weights": parse_path_weights(getattr(args, "path_weights", "1,1,1")),
            }
        )
    return config


def open_udp_socket(bind_ip: str, bind_port: int, socket_buffer: int = 4 * 1024 * 1024) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, socket_buffer)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, socket_buffer)
    sock.bind((bind_ip, bind_port))
    return sock


def choose_sender_mode(args: argparse.Namespace) -> str:
    if args.send_mode != "auto":
        return args.send_mode
    if int(args.strategy) in IP_ID_STRATEGIES:
        return "scapy-l2"
    return "socket"


def choose_receiver_mode(args: argparse.Namespace) -> str:
    if args.receive_mode != "auto":
        return args.receive_mode
    if int(args.strategy) in IP_ID_STRATEGIES or int(args.strategy) == 3:
        return "sniff"
    return "socket" if not args.iface else "sniff"


def timing_tag_prefix(pkt: PacketSpec) -> bytes:
    """策略0/1的 PacketSpec payload 前 2 字节是方案B同步标签。"""

    return pkt.payload[:2]


def build_strategy3_payload(pkt: PacketSpec, business_payload: bytes) -> Tuple[bytes, bool]:
    """把策略3同步小头和原始业务载荷封装到同一个 UDP payload 中。"""

    header = pkt.payload[:STRATEGY3_HEADER_LEN]
    body = len(business_payload).to_bytes(STRATEGY3_PROXY_LEN_BYTES, "big") + business_payload
    payload = header + body
    oversized = False
    if pkt.target_packet_length is not None:
        target_payload_len = max(0, int(pkt.target_packet_length) - IP_UDP_HEADER_BYTES)
        if len(payload) > target_payload_len:
            oversized = True
            target_payload_len = len(payload)
        if len(payload) < target_payload_len:
            pad_seed = pkt.payload[STRATEGY3_HEADER_LEN:] or b"\x00"
            padding = bytearray()
            while len(padding) < target_payload_len - len(payload):
                padding.extend(pad_seed)
            payload += bytes(padding[: target_payload_len - len(payload)])
    return payload, oversized


def build_proxy_payload(pkt: PacketSpec, business_payload: bytes, strategy_id: int) -> Tuple[bytes, bool]:
    """根据策略把隐蔽字段叠加到真实业务 payload 上。"""

    if strategy_id in TIMING_STRATEGIES:
        return timing_tag_prefix(pkt) + business_payload, False
    if strategy_id == 3:
        return build_strategy3_payload(pkt, business_payload)
    return business_payload, False


def extract_business_payload(payload: bytes, strategy_id: int) -> bytes:
    """接收端剥离代理层隐蔽小头，还原原始业务 payload。"""

    if strategy_id in TIMING_STRATEGIES:
        return payload[2:] if len(payload) >= 2 else b""
    if strategy_id == 3:
        offset = STRATEGY3_HEADER_LEN
        if len(payload) < offset + STRATEGY3_PROXY_LEN_BYTES:
            return b""
        original_len = int.from_bytes(payload[offset : offset + STRATEGY3_PROXY_LEN_BYTES], "big")
        start = offset + STRATEGY3_PROXY_LEN_BYTES
        return payload[start : start + original_len]
    return payload


def parse_proxy_tag(
    payload: bytes,
    strategy_id: int,
    seq_num: int,
    expected_units: int,
    sync_key: int,
) -> bool:
    """判断 socket 接收模式下的 payload 是否带当前隐蔽帧同步标签。"""

    tag = parse_timing_tag(payload, strategy_id, sync_key)
    if tag is None:
        return False
    if tag.frame_id != (seq_num & 0x0F):
        return False
    if tag.phase == ANCHOR_PHASE:
        return True
    return 0 <= tag.symbol_index < expected_units


class ScapyL2Sender:
    """用 Scapy 二层发送，便于显式控制 IPv4 ID。"""

    def __init__(self, args: argparse.Namespace):
        if not args.iface:
            raise ValueError("scapy-l2 模式必须指定 --iface")
        from scapy.all import Ether, IP, UDP, Raw, conf, get_if_hwaddr

        conf.verb = 0
        self._ether_cls = Ether
        self._ip_cls = IP
        self._udp_cls = UDP
        self._raw_cls = Raw
        self.iface = args.iface
        self.src_mac = args.src_mac or get_if_hwaddr(args.iface)
        self.dst_mac = args.dst_mac
        self.src_ip = args.src_ip
        self.dst_ip = args.remote_ip
        self.dport = int(args.remote_port)
        self.send_gap_ms = float(getattr(args, "l2_send_gap_ms", 0.0))
        self._last_send_at = 0.0
        self._socket = conf.L2socket(iface=self.iface)

    def send(self, payload: bytes, ip_id: int, sport: int) -> None:
        if self.send_gap_ms > 0 and self._last_send_at > 0:
            wait_s = self.send_gap_ms / 1000.0 - (time.time() - self._last_send_at)
            if wait_s > 0:
                time.sleep(wait_s)
        ip = self._ip_cls(dst=self.dst_ip, id=int(ip_id) & 0xFFFF)
        if self.src_ip:
            ip.src = self.src_ip
        frame = (
            self._ether_cls(src=self.src_mac, dst=self.dst_mac)
            / ip
            / self._udp_cls(sport=int(sport) & 0xFFFF, dport=self.dport)
            / self._raw_cls(payload)
        )
        self._socket.send(frame)
        self._last_send_at = time.time()

    def close(self) -> None:
        """关闭持久二层发送 socket。"""

        try:
            self._socket.close()
        except OSError:
            pass


def sleep_for_packet(index: int, pkt: PacketSpec) -> None:
    """按照策略给出的相对间隔控制发送节奏。"""

    if index <= 0:
        return
    delay_ms = float(pkt.send_delay_ms)
    if delay_ms > 0:
        time.sleep(delay_ms / 1000.0)


def run_sender(args: argparse.Namespace) -> int:
    hidden_data = Path(args.hidden_input).read_bytes()
    strategy_id = int(args.strategy)
    strategy = get_strategy(StrategyID(strategy_id), config=build_strategy_config(args, len(hidden_data)))
    covert_packets = strategy.encode(hidden_data, path_id=int(args.path_id), seq_num=int(args.seq_num))
    sender_mode = choose_sender_mode(args)

    listen_sock = open_udp_socket(args.listen_ip, args.listen_port, args.socket_buffer)
    listen_sock.settimeout(0.2)
    socket_sender: Optional[socket.socket] = None
    scapy_sender: Optional[ScapyL2Sender] = None
    if sender_mode == "socket":
        if strategy_id in IP_ID_STRATEGIES:
            raise ValueError("策略2/4/5必须使用 scapy-l2 才能写 IPv4 ID")
        socket_sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        socket_sender.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, args.socket_buffer)
    else:
        scapy_sender = ScapyL2Sender(args)

    remote = (args.remote_ip, int(args.remote_port))
    total_business_packets = 0
    covert_packets_sent = 0
    covert_business_packets_sent = 0
    plain_packets_sent = 0
    dropped_covert_packets = 0
    strategy3_oversized_packets = 0
    started_at = time.time()
    last_packet_at = started_at
    schedule_index = 0
    repeat_index = 0

    while True:
        now = time.time()
        if total_business_packets > 0 and now - last_packet_at >= float(args.max_idle):
            break
        try:
            business_payload, source_addr = listen_sock.recvfrom(65535)
        except socket.timeout:
            continue

        total_business_packets += 1
        last_packet_at = time.time()
        sport = int(args.sport) if int(args.sport) > 0 else int(source_addr[1])

        if schedule_index < len(covert_packets):
            pkt = covert_packets[schedule_index]
            if repeat_index == 0:
                sleep_for_packet(schedule_index, pkt)
            proxy_payload, oversized = build_proxy_payload(pkt, business_payload, strategy_id)
            if oversized:
                strategy3_oversized_packets += 1
            should_drop = (
                int(args.drop_tagged_every) > 0
                and covert_packets_sent > 0
                and covert_packets_sent % int(args.drop_tagged_every) == 0
            )
            if should_drop:
                dropped_covert_packets += 1
            else:
                ip_id = pkt.ip_id_field if pkt.ip_id_field is not None else ((0x2000 + total_business_packets) & 0x7FFF)
                if socket_sender is not None:
                    socket_sender.sendto(proxy_payload, remote)
                elif scapy_sender is not None:
                    scapy_sender.send(proxy_payload, ip_id=ip_id, sport=sport)
            covert_business_packets_sent += 1
            repeat_index += 1
            if strategy_id in TIMING_STRATEGIES:
                repeat_target = max(1, int(args.timing_repeat))
            elif strategy_id == 5:
                repeat_target = max(1, int(args.path_sequence_repeat))
            else:
                repeat_target = 1
            if repeat_index >= repeat_target:
                covert_packets_sent += 1
                schedule_index += 1
                repeat_index = 0
        else:
            plain_payload = business_payload
            if socket_sender is not None:
                socket_sender.sendto(plain_payload, remote)
            elif scapy_sender is not None:
                ip_id = (0x1000 + total_business_packets) & 0x7FFF
                scapy_sender.send(plain_payload, ip_id=ip_id, sport=sport)
            plain_packets_sent += 1

    listen_sock.close()
    if socket_sender is not None:
        socket_sender.close()
    if scapy_sender is not None:
        scapy_sender.close()

    summary = {
        "mode": "sender",
        "sender_mode": sender_mode,
        "strategy_id": strategy_id,
        "hidden_bytes": len(hidden_data),
        "covert_packets_required": len(covert_packets),
        "business_packets_received": total_business_packets,
        "covert_packets_sent": covert_packets_sent,
        "covert_business_packets_sent": covert_business_packets_sent,
        "dropped_covert_packets": dropped_covert_packets,
        "plain_packets_sent": plain_packets_sent,
        "strategy3_oversized_packets": strategy3_oversized_packets,
        "complete": covert_packets_sent >= len(covert_packets),
        "duration_s": round(time.time() - started_at, 3),
        "strategy_config": build_strategy_config(args, len(hidden_data)),
    }
    summary_path = Path(args.summary)
    ensure_parent(summary_path)
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["complete"] else 2


def wait_segment_permission(control_dir: Optional[str], segment_id: int, timeout_s: float = 30.0) -> None:
    """等待控制脚本完成当前分段的路径切换。"""

    if not control_dir:
        return
    control_path = Path(control_dir)
    ready = control_path / f"segment_{segment_id}.ready"
    done = control_path / f"segment_{segment_id}.done"
    control_path.mkdir(parents=True, exist_ok=True)
    ready.write_text("ready\n", encoding="utf-8")
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if done.exists():
            return
        time.sleep(0.05)
    raise TimeoutError(f"等待 segment {segment_id} 路径切换超时")


def mark_all_segments_done(control_dir: Optional[str]) -> None:
    """通知控制脚本：所有隐蔽分段已经挂载完成，后续只剩普通业务转发。"""

    if not control_dir:
        return
    control_path = Path(control_dir)
    control_path.mkdir(parents=True, exist_ok=True)
    (control_path / "all_segments.done").write_text("done\n", encoding="utf-8")


def run_plan_sender(args: argparse.Namespace) -> int:
    """持续接收真实 UDP 业务包，并按多策略计划把隐蔽数据挂载到业务包上。"""

    plan = load_proxy_plan(args.plan_file)
    segments = list(plan["segments"])
    encoded_segments = []
    for segment in segments:
        encoded_segments.append(
            {
                "segment": dict(segment),
                "packets": [],
                "config": {},
                "index": 0,
                "repeat": 0,
                "started": False,
                "complete": False,
                "covert_business_packets": 0,
            }
        )

    listen_sock = open_udp_socket(args.listen_ip, args.listen_port, args.socket_buffer)
    listen_sock.settimeout(0.2)
    scapy_sender = ScapyL2Sender(
        argparse.Namespace(
            iface=args.iface,
            src_mac=args.src_mac,
            dst_mac=args.dst_mac,
            src_ip=args.src_ip,
            remote_ip=args.remote_ip,
            remote_port=int(args.plain_remote_port),
            l2_send_gap_ms=float(args.l2_send_gap_ms),
        )
    )

    current_segment = 0
    total_business_packets = 0
    plain_packets = 0
    covert_packets_sent = 0
    started_at = time.time()
    last_packet_at = started_at
    all_segments_completed_at: Optional[float] = None

    while True:
        if current_segment >= len(encoded_segments):
            if all_segments_completed_at is None:
                all_segments_completed_at = time.time()
        try:
            business_payload, source_addr = listen_sock.recvfrom(65535)
        except socket.timeout:
            if (
                current_segment >= len(encoded_segments)
                and time.time() - last_packet_at >= float(args.max_idle)
            ):
                break
            continue

        total_business_packets += 1
        last_packet_at = time.time()
        sport = int(args.sport) if int(args.sport) > 0 else int(source_addr[1])

        if current_segment < len(encoded_segments):
            item = encoded_segments[current_segment]
            segment = item["segment"]
            strategy_id = int(segment["strategy_id"])
            if not item["started"]:
                wait_segment_permission(args.control_dir, int(segment["segment_id"]))
                _latest_plan, latest_segment = load_proxy_segment(
                    args.plan_file,
                    int(segment["segment_id"]),
                )
                packets, config = encode_plan_segment(latest_segment, int(args.sync_key))
                item["segment"] = latest_segment
                item["packets"] = packets
                item["config"] = config
                item["index"] = 0
                item["repeat"] = 0
                segment = item["segment"]
                strategy_id = int(segment["strategy_id"])
                item["started"] = True
            packets: List[PacketSpec] = item["packets"]
            if not packets:
                item["complete"] = True
                current_segment += 1
                continue
            pkt = packets[int(item["index"])]
            if int(item["repeat"]) == 0:
                sleep_for_packet(int(item["index"]), pkt)
            proxy_payload, _oversized = build_proxy_payload(pkt, business_payload, strategy_id)
            remote_port = int(segment.get("remote_port", args.plain_remote_port))
            scapy_sender.dport = remote_port
            ip_id = pkt.ip_id_field if pkt.ip_id_field is not None else ((0x2000 + total_business_packets) & 0x7FFF)
            scapy_sender.send(proxy_payload, ip_id=ip_id, sport=sport)
            item["covert_business_packets"] += 1

            if strategy_id in TIMING_STRATEGIES:
                repeat_target = max(1, int(segment.get("repeat", args.timing_repeat)))
            elif strategy_id == 5:
                repeat_target = max(1, int(segment.get("repeat", args.path_sequence_repeat)))
            else:
                repeat_target = 1
            item["repeat"] = int(item["repeat"]) + 1
            if int(item["repeat"]) >= repeat_target:
                item["index"] = int(item["index"]) + 1
                item["repeat"] = 0
                covert_packets_sent += 1
            if int(item["index"]) >= len(packets):
                item["complete"] = True
                current_segment += 1
                if current_segment >= len(encoded_segments):
                    all_segments_completed_at = time.time()
                    mark_all_segments_done(args.control_dir)
            continue

        scapy_sender.dport = int(args.plain_remote_port)
        try:
            scapy_sender.send(
                business_payload,
                ip_id=(0x1000 + total_business_packets) & 0x7FFF,
                sport=sport,
            )
        except OSError:
            if current_segment >= len(encoded_segments):
                break
            raise
        plain_packets += 1

    listen_sock.close()
    scapy_sender.close()
    summary = {
        "mode": "plan-sender",
        "complete": all(bool(item["complete"]) for item in encoded_segments),
        "segments_total": len(encoded_segments),
        "segments_complete": sum(1 for item in encoded_segments if item["complete"]),
        "business_packets_received": total_business_packets,
        "covert_packets_sent": covert_packets_sent,
        "plain_packets_sent": plain_packets,
        "duration_s": round(time.time() - started_at, 3),
        "segments": [
            {
                "segment_id": int(item["segment"]["segment_id"]),
                "strategy_id": int(item["segment"]["strategy_id"]),
                "remote_port": int(item["segment"].get("remote_port", 0)),
                "paths": [int(path) for path in item["segment"].get("paths", [])],
                "packets_required": len(item["packets"]),
                "covert_business_packets": int(item["covert_business_packets"]),
                "complete": bool(item["complete"]),
            }
            for item in encoded_segments
        ],
    }
    summary_path = Path(args.summary)
    ensure_parent(summary_path)
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["complete"] else 2


class SocketDrain:
    """抓包模式下绑定代理端口，避免内核回复 ICMP port unreachable。"""

    def __init__(self, bind_ip: str, bind_port: int):
        self.sock = open_udp_socket(bind_ip, bind_port)
        self.sock.settimeout(0.2)
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def close(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=1.0)
        self.sock.close()

    def _run(self) -> None:
        while not self.stop_event.is_set():
            try:
                self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break


class Strategy2FragmentTracker:
    """根据策略2 IP-ID 的 seq_mod 序列推断逻辑片段号。"""

    def __init__(self):
        self._block_id = 0
        self._last_seq = -1

    def infer(self, ip_id: int) -> int:
        seq_mod = (int(ip_id) >> 8) & 0x0F
        inferred_block = self._block_id
        if self._last_seq >= 12 and seq_mod <= 3:
            self._block_id += 1
            inferred_block = self._block_id
        elif self._last_seq <= 3 and seq_mod >= 12 and self._block_id > 0:
            # 低序号刚到后又出现高序号，通常是上一块的迟到包。
            inferred_block = self._block_id - 1
        self._last_seq = seq_mod
        return inferred_block * 16 + seq_mod


def build_router(args: argparse.Namespace) -> StrategyReceiverRouter:
    config = build_strategy_config(args, getattr(args, "expected_bytes", None))
    strategy_id = int(args.strategy)
    timing_enabled = strategy_id in TIMING_STRATEGIES
    return StrategyReceiverRouter(
        strategy_configs={strategy_id: config},
        sync_key=int(args.sync_key),
        timing_ports={0: None, 1: None} if timing_enabled else {0: -1, 1: -1},
        accept_timing_without_port=timing_enabled,
    )


def expected_timing_units(args: argparse.Namespace) -> int:
    """计算策略0/1当前隐蔽帧允许出现的最大承载包编号，降低普通业务误判。

    两字节时序同步标签中的 symbol_index 不是隐蔽符号编号，而是策略编码后
    的承载包编号。策略0每 1 bit 需要滑动 4 包窗口，策略1每 2 bit 需要
    一个滑动窗口，因此最后几个尾包的编号会大于隐蔽符号数量。这里按
    编码器的承载包数量放宽过滤，否则接收端会把尾包当普通业务包剥离，
    导致策略0/1只能解出前半段。
    """

    if args.expected_bytes is None:
        return 255
    block_symbols = 8
    if int(args.strategy) == 0:
        symbols = int(args.expected_bytes) * 8
    else:
        symbols = int(args.expected_bytes) * 4
    blocks = (symbols + block_symbols - 1) // block_symbols
    return symbols + 3 * blocks


def mark_current_strategy_packet(
    args: argparse.Namespace,
    payload: bytes,
    metadata: dict,
    strategy2_tracker: Strategy2FragmentTracker,
) -> bool:
    """
    判断当前包是否属于正在验证/运行的策略。

    真实业务流中会有大量普通 UDP 包。这里故意只识别当前策略，避免普通业务
    payload 或随机 IP-ID 被其他策略误判后污染解码缓冲区。
    """

    strategy_id = int(args.strategy)
    config = build_strategy_config(args, getattr(args, "expected_bytes", None))

    if strategy_id in TIMING_STRATEGIES:
        return parse_proxy_tag(
            payload,
            strategy_id,
            int(args.seq_num),
            expected_timing_units(args),
            int(args.sync_key),
        )

    if strategy_id == 2:
        from python.covert_strategies.protocol_high_reliability import (
            ProtocolHighReliabilityStrategy,
        )

        probe = ProtocolHighReliabilityStrategy(config)
        parsed = probe._unpack_ip_id(int(metadata.get("ip_id", 0)))
        if parsed is None:
            return False
        metadata["fragment_id"] = strategy2_tracker.infer(int(metadata["ip_id"]))
        metadata["ip_id_info"] = parsed
        return True

    if strategy_id == 3:
        from python.covert_strategies.statistical_fusion import StatisticalFusionStrategy

        probe = StatisticalFusionStrategy(config)
        tag = probe._parse_tag(payload)
        if tag is None or int(tag.seq_num) != (int(args.seq_num) & 0xFF):
            return False
        metadata["fusion_tag"] = {
            "seq_num": tag.seq_num,
            "symbol_index": tag.symbol_index,
            "total_symbols": tag.total_symbols,
            "total_bits": tag.total_bits,
            "repeat_index": tag.repeat_index,
        }
        return True

    if strategy_id == 4:
        from python.covert_strategies.full_path_redundancy import FullPathRedundancyStrategy

        probe = FullPathRedundancyStrategy(config)
        parsed = probe._unpack_ip_id(int(metadata.get("ip_id", 0)))
        if parsed is None:
            return False
        metadata["ip_id_info"] = parsed
        metadata["frame_id"] = parsed["frame_id"]
        metadata["symbol_id"] = parsed["symbol_id"]
        return True

    if strategy_id == 5:
        from python.covert_strategies.path_sequence import PathSequenceStrategy

        probe = PathSequenceStrategy(config)
        parsed = probe.parse_ip_id(int(metadata.get("ip_id", 0)))
        if parsed is None:
            return False
        metadata["path_id"] = parsed["path_id"]
        metadata["fragment_id"] = parsed["fragment_id_mod"]
        metadata["ip_id_info"] = parsed
        return True

    return False


def run_socket_receiver(args: argparse.Namespace) -> int:
    """兼容策略0/1的普通 UDP socket 接收模式。"""

    if int(args.strategy) not in TIMING_STRATEGIES:
        raise ValueError("socket 接收模式只适合策略0/1；策略2/3/4/5请使用 --receive-mode sniff")
    expected_units = expected_timing_units(args)
    strategy = get_strategy(
        StrategyID(int(args.strategy)),
        config=build_strategy_config(args, getattr(args, "expected_bytes", None)),
    )
    listen_sock = open_udp_socket(args.listen_ip, args.listen_port)
    listen_sock.settimeout(0.2)
    forward_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    forward_target = (args.forward_ip, int(args.forward_port))

    captured_payloads: List[bytes] = []
    metadata: List[dict] = []
    first_tagged_time: Optional[float] = None
    started_at = time.time()
    last_packet_at = started_at
    total_packets = 0
    tagged_packets = 0
    plain_packets = 0
    forwarded_packets = 0

    while True:
        now = time.time()
        if now - started_at >= float(args.timeout):
            break
        if total_packets > 0 and now - last_packet_at >= float(args.max_idle):
            break
        try:
            proxy_payload, _addr = listen_sock.recvfrom(65535)
        except socket.timeout:
            continue

        total_packets += 1
        last_packet_at = time.time()
        is_tagged = parse_proxy_tag(proxy_payload, int(args.strategy), int(args.seq_num), expected_units, int(args.sync_key))
        if is_tagged:
            if first_tagged_time is None:
                first_tagged_time = last_packet_at
            arrival_time_ms = (last_packet_at - first_tagged_time) * 1000.0
            captured_payloads.append(proxy_payload[:2])
            metadata.append({"arrival_time_ms": arrival_time_ms, "proxy_packet_index": total_packets - 1})
            forward_payload = extract_business_payload(proxy_payload, int(args.strategy))
            tagged_packets += 1
        else:
            forward_payload = proxy_payload
            plain_packets += 1
        forward_sock.sendto(forward_payload, forward_target)
        forwarded_packets += 1

    listen_sock.close()
    forward_sock.close()
    decoded = strategy.decode(captured_payloads, metadata)
    return write_receiver_summary(args, decoded, {
        "receiver_mode": "socket",
        "packets_received": total_packets,
        "covert_packets": tagged_packets,
        "plain_packets": plain_packets,
        "forwarded_business_packets": forwarded_packets,
        "decode_info": getattr(strategy, "last_decode_info", {}),
    })


def run_sniff_receiver(args: argparse.Namespace) -> int:
    """抓包接收模式，可解析 IP-ID、包长和时序三类策略。"""

    if not args.iface:
        raise ValueError("sniff 接收模式必须指定 --iface")
    from scapy.all import IP, UDP, Raw, sniff

    router = build_router(args)
    drain = SocketDrain(args.listen_ip, int(args.listen_port))
    drain.start()
    forward_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    forward_target = (args.forward_ip, int(args.forward_port))
    strategy2_tracker = Strategy2FragmentTracker()

    started_at = time.time()
    first_packet_time: Optional[float] = None
    last_packet_at = started_at
    total_packets = 0
    covert_packets = 0
    plain_packets = 0
    forwarded_packets = 0

    def handle_packet(packet) -> None:
        nonlocal first_packet_time, last_packet_at
        nonlocal total_packets, covert_packets, plain_packets, forwarded_packets

        if IP not in packet or UDP not in packet:
            return
        if int(packet[UDP].dport) != int(args.listen_port):
            return
        payload = bytes(packet[Raw].load) if Raw in packet else b""
        packet_time = float(packet.time)
        if first_packet_time is None:
            first_packet_time = packet_time
        last_packet_at = time.time()
        total_packets += 1

        ip_id = int(packet[IP].id)
        metadata = {
            "arrival_time_ms": (packet_time - first_packet_time) * 1000.0,
            "ip_id": ip_id,
            "packet_length": int(packet[IP].len),
            "sport": int(packet[UDP].sport),
            "dport": int(packet[UDP].dport),
            "message_key": int(args.seq_num),
            "sequence_num": int(args.seq_num),
        }
        is_current_covert = mark_current_strategy_packet(args, payload, metadata, strategy2_tracker)
        if is_current_covert:
            metadata["force_strategy_id"] = int(args.strategy)
            routed = router.ingest(payload, metadata)
        else:
            routed = None

        if routed is not None and int(routed.strategy_id) == int(args.strategy):
            forward_payload = extract_business_payload(payload, int(args.strategy))
            covert_packets += 1
        else:
            forward_payload = payload
            plain_packets += 1
        forward_sock.sendto(forward_payload, forward_target)
        forwarded_packets += 1

    deadline = started_at + float(args.timeout)
    bpf_filter = f"udp and dst port {int(args.listen_port)}"
    try:
        while time.time() < deadline:
            sniff(iface=args.iface, filter=bpf_filter, prn=handle_packet, timeout=0.5, store=False)
            if total_packets > 0 and time.time() - last_packet_at >= float(args.max_idle):
                break
    finally:
        drain.close()
        forward_sock.close()

    decode_results = router.decode_all()
    decoded = None
    for result in decode_results:
        if result.success and int(result.strategy_id) == int(args.strategy):
            decoded = result.decoded
            break

    return write_receiver_summary(args, decoded, {
        "receiver_mode": "sniff",
        "packets_received": total_packets,
        "covert_packets": covert_packets,
        "plain_packets": plain_packets,
        "forwarded_business_packets": forwarded_packets,
        "router_summary": router.summary(),
        "decode_results": [result.to_dict() for result in decode_results],
    })


def run_plan_receiver(args: argparse.Namespace) -> int:
    """自动识别多个策略分段，解码隐蔽数据并保持业务流转发。"""

    if not args.iface:
        raise ValueError("plan-receiver 必须指定 --iface")
    from scapy.all import IP, UDP, Raw, sniff

    plan_path = Path(args.plan_file)
    plan_mtime = -1.0
    plan = {}
    segments: List[dict] = []
    segment_by_port: Dict[int, dict] = {}
    plain_ports: set[int] = set()
    all_ports: set[int] = set()

    def refresh_plan(force: bool = False) -> None:
        """按需重新加载计划文件，支持传输过程中的 chunk 级策略切换。"""

        nonlocal plan_mtime, plan, segments, segment_by_port, plain_ports, all_ports
        try:
            current_mtime = plan_path.stat().st_mtime
        except OSError:
            if force:
                raise
            return
        if not force and current_mtime == plan_mtime:
            return
        loaded = load_proxy_plan(str(plan_path))
        loaded_segments = list(loaded["segments"])
        plan = loaded
        segments = loaded_segments
        segment_by_port = {int(item["remote_port"]): item for item in loaded_segments}
        plain_ports = set(int(item) for item in loaded.get("plain_ports", []))
        all_ports = set(segment_by_port) | plain_ports
        plan_mtime = current_mtime

    refresh_plan(force=True)
    initial_ports = set(all_ports)
    if not initial_ports:
        raise ValueError("plan-file 没有可监听的 UDP 端口")
    min_port = min(initial_ports)
    max_port = max(initial_ports)

    router = StrategyReceiverRouter(
        strategy_configs={},
        sync_key=int(args.sync_key),
        timing_ports={},
        accept_timing_without_port=False,
    )

    drains = []
    for port in initial_ports:
        drain = SocketDrain(args.listen_ip, int(port))
        drain.start()
        drains.append(drain)

    forward_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    forward_target = (args.forward_ip, int(args.forward_port))
    strategy2_trackers: Dict[int, Strategy2FragmentTracker] = {}
    started_at = time.time()
    first_packet_time: Optional[float] = None
    last_packet_at = started_at
    total_packets = 0
    covert_packets = 0
    plain_packets = 0
    forwarded_packets = 0
    per_segment_packets: Dict[int, int] = {}

    def handle_packet(packet) -> None:
        nonlocal first_packet_time, last_packet_at
        nonlocal total_packets, covert_packets, plain_packets, forwarded_packets

        if IP not in packet or UDP not in packet:
            return
        refresh_plan()
        dport = int(packet[UDP].dport)
        if dport not in all_ports:
            return
        payload = bytes(packet[Raw].load) if Raw in packet else b""
        packet_time = float(packet.time)
        if first_packet_time is None:
            first_packet_time = packet_time
        last_packet_at = time.time()
        total_packets += 1

        segment = segment_by_port.get(dport)
        if segment is None:
            forward_sock.sendto(payload, forward_target)
            plain_packets += 1
            forwarded_packets += 1
            return

        segment_id = int(segment["segment_id"])
        strategy_id = int(segment["strategy_id"])
        per_segment_packets[segment_id] = per_segment_packets.get(segment_id, 0) + 1
        metadata = {
            "arrival_time_ms": (packet_time - first_packet_time) * 1000.0,
            "ip_id": int(packet[IP].id),
            "packet_length": int(packet[IP].len),
            "sport": int(packet[UDP].sport),
            "dport": dport,
            "message_key": int(segment.get("sequence_num", 1)),
            "sequence_num": int(segment.get("sequence_num", 1)),
            "expected_bytes": int(segment.get("expected_bytes", 0)),
            "business_payload_len": 32,
            "sync_key": int(args.sync_key),
        }
        metadata.update(strategy_config_for_segment(segment, int(args.sync_key)))
        metadata["force_strategy_id"] = strategy_id
        if strategy_id == 2:
            tracker = strategy2_trackers.setdefault(segment_id, Strategy2FragmentTracker())
            metadata["fragment_id"] = tracker.infer(int(metadata["ip_id"]))

        routed = router.ingest(payload, metadata)
        if routed is not None:
            forward_payload = extract_business_payload(payload, strategy_id)
            covert_packets += 1
        else:
            forward_payload = payload
            plain_packets += 1
        forward_sock.sendto(forward_payload, forward_target)
        forwarded_packets += 1

    bpf_filter = f"udp portrange {min_port}-{max_port}"
    try:
        deadline = started_at + float(args.timeout)
        while time.time() < deadline:
            sniff(iface=args.iface, filter=bpf_filter, prn=handle_packet, timeout=0.5, store=False)
            if total_packets > 0 and time.time() - last_packet_at >= float(args.max_idle):
                break
    finally:
        for drain in drains:
            drain.close()
        forward_sock.close()

    decode_results = router.decode_all()
    decoded_by_key = {
        int(result.message_key): result.decoded
        for result in decode_results
        if result.success and result.decoded is not None
    }
    output_parts = []
    missing_segments = []
    for segment in sorted(segments, key=lambda item: int(item["segment_id"])):
        key = int(segment.get("sequence_num", 1))
        decoded = decoded_by_key.get(key)
        if decoded is None:
            missing_segments.append(int(segment["segment_id"]))
            continue
        output_parts.append(decoded)
    final_output = b"".join(output_parts)

    output_path = Path(args.hidden_output)
    summary_path = Path(args.summary)
    ensure_parent(output_path)
    ensure_parent(summary_path)
    if final_output:
        output_path.write_bytes(final_output)

    expected_hidden = bytes.fromhex(str(plan.get("hidden_hex", "")))
    hidden_match = bool(expected_hidden) and final_output == expected_hidden
    summary = {
        "mode": "plan-receiver",
        "success": not missing_segments and (hidden_match if expected_hidden else bool(final_output)),
        "hidden_decoded_bytes": len(final_output),
        "hidden_output": str(output_path),
        "hidden_match": hidden_match if expected_hidden else None,
        "missing_segments": missing_segments,
        "packets_received": total_packets,
        "covert_packets": covert_packets,
        "plain_packets": plain_packets,
        "forwarded_business_packets": forwarded_packets,
        "per_segment_packets": per_segment_packets,
        "router_summary": router.summary(),
        "decode_results": [result.to_dict() for result in decode_results],
    }
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["success"] else 1


def write_receiver_summary(args: argparse.Namespace, decoded: Optional[bytes], extra: dict) -> int:
    output_path = Path(args.hidden_output)
    ensure_parent(output_path)
    if decoded is not None:
        output_path.write_bytes(decoded)

    summary = {
        "mode": "receiver",
        "strategy_id": int(args.strategy),
        "hidden_decoded_bytes": len(decoded) if decoded is not None else 0,
        "hidden_output": str(output_path),
        "success": decoded is not None,
        "strategy_config": build_strategy_config(args, getattr(args, "expected_bytes", None)),
    }
    summary.update(extra)
    summary_path = Path(args.summary)
    ensure_parent(summary_path)
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if decoded is not None else 1


def run_receiver(args: argparse.Namespace) -> int:
    receiver_mode = choose_receiver_mode(args)
    if receiver_mode == "socket":
        return run_socket_receiver(args)
    return run_sniff_receiver(args)


def main() -> int:
    args = parse_args()
    if args.mode == "sender":
        return run_sender(args)
    if args.mode == "receiver":
        return run_receiver(args)
    if args.mode == "plan-sender":
        return run_plan_sender(args)
    if args.mode == "plan-receiver":
        return run_plan_receiver(args)
    raise ValueError(f"未知模式：{args.mode}")


if __name__ == "__main__":
    raise SystemExit(main())
