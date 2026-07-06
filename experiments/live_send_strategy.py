"""
真实网络单策略发送脚本。

在 Mininet/BMv2 中建议在 h1 上运行。脚本读取输入文件，调用指定策略生成 PacketSpec，
再把每个包作为 UDP 业务流发出去。策略2和策略4需要控制 IPv4 ID 字段，推荐使用 scapy-l2 模式。
"""

import argparse
import time
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from python.covert_strategies.base import StrategyID
from python.covert_strategies.strategy_registry import get_strategy


def parse_path_weights(raw: str):
    """把 1,1,0 形式的权重字符串解析为三条链路的整数权重。"""
    values = [item.strip() for item in raw.split(",") if item.strip()]
    weights = [max(0, int(item)) for item in values[:3]]
    while len(weights) < 3:
        weights.append(0)
    if sum(weights) == 0:
        return [1, 1, 1]
    return weights


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="真实网络单策略发送端")
    parser.add_argument("--strategy", type=int, required=True, choices=[0, 1, 2, 3, 4, 5])
    parser.add_argument("--input", default="experiments/data/input_message.txt")
    parser.add_argument("--dst-ip", required=True)
    parser.add_argument("--src-ip", default=None)
    parser.add_argument("--iface", default=None)
    parser.add_argument("--src-mac", default=None)
    parser.add_argument("--dst-mac", default="00:00:00:00:01:01")
    parser.add_argument("--path-id", type=int, default=0)
    parser.add_argument("--seq-num", type=int, default=1)
    parser.add_argument("--sport", type=int, default=40000)
    parser.add_argument("--dport", type=int, default=None)
    parser.add_argument("--sync-key", type=lambda x: int(x, 0), default=0x5A17)
    parser.add_argument("--secret-key", default=None, help="策略2/4等需要加密时使用的字符串密钥")
    parser.add_argument("--business-payload-len", type=int, default=32, help="每个承载包的UDP载荷长度")
    parser.add_argument("--strategy4-k", type=int, default=None, help="策略4每个frame的源半字节数量")
    parser.add_argument("--strategy4-num-output", type=int, default=None, help="策略4每个frame生成的喷泉符号数")
    parser.add_argument("--path-weights", default=None, help="策略4离线分配路径用的权重，例如 1,1,0")
    parser.add_argument(
        "--send-mode",
        choices=["socket", "scapy", "scapy-l2"],
        default="socket",
        help="socket 更稳定；scapy-l2 能稳定控制 IP ID，适合策略2/4验证",
    )
    parser.add_argument("--pace-ms", type=float, default=0.0, help="每个包之间额外补充的最小发送间隔，单位毫秒")
    parser.add_argument("--dry-run", action="store_true", help="只打印包数量，不实际发送")
    return parser.parse_args()


def build_strategy_config(args: argparse.Namespace) -> dict:
    """根据命令行参数生成策略配置，未使用的字段会被对应策略自然忽略。"""
    config = {
        "sync_key": args.sync_key,
        "business_payload_len": args.business_payload_len,
    }
    if args.secret_key:
        config["secret_key"] = args.secret_key
    if args.strategy4_k is not None:
        config["k"] = args.strategy4_k
    if args.strategy4_num_output is not None:
        config["num_output"] = args.strategy4_num_output
    if args.path_weights:
        config["path_weights"] = parse_path_weights(args.path_weights)
    return config


def _packet_payload(pkt) -> bytes:
    payload = pkt.payload
    if pkt.target_packet_length is not None:
        target_payload_len = max(len(payload), pkt.target_packet_length - 20 - 8)
        if len(payload) < target_payload_len:
            payload += bytes(
                (i * 31 + pkt.fragment_id) & 0xFF
                for i in range(target_payload_len - len(payload))
            )
    return payload


def _sleep_before_packet(index: int, pkt, pace_ms: float) -> None:
    if index <= 0:
        return
    gap_ms = max(float(pkt.send_delay_ms), float(pace_ms))
    if gap_ms > 0:
        time.sleep(gap_ms / 1000.0)


def _send_with_socket(args: argparse.Namespace, packets, dport: int) -> None:
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if args.src_ip:
        sock.bind((args.src_ip, args.sport))
    else:
        sock.bind(("0.0.0.0", args.sport))

    target = (args.dst_ip, dport)
    for index, pkt in enumerate(packets):
        _sleep_before_packet(index, pkt, args.pace_ms)
        sock.sendto(_packet_payload(pkt), target)
    sock.close()


def _send_with_scapy(args: argparse.Namespace, packets, dport: int) -> None:
    from scapy.all import IP, UDP, Raw, conf, send

    conf.verb = 0
    for index, pkt in enumerate(packets):
        _sleep_before_packet(index, pkt, args.pace_ms)
        ip_id = pkt.ip_id_field if pkt.ip_id_field is not None else (0x1000 + index) & 0xFFFF
        ip = IP(dst=args.dst_ip, id=ip_id)
        if args.src_ip:
            ip.src = args.src_ip
        packet = ip / UDP(sport=args.sport, dport=dport) / Raw(_packet_payload(pkt))
        send(packet, iface=args.iface, verbose=False)


def _send_with_scapy_l2(args: argparse.Namespace, packets, dport: int) -> None:
    from scapy.all import Ether, IP, UDP, Raw, conf, get_if_hwaddr, sendp

    if not args.iface:
        raise ValueError("scapy-l2 模式必须指定 --iface")
    conf.verb = 0
    src_mac = args.src_mac or get_if_hwaddr(args.iface)
    for index, pkt in enumerate(packets):
        _sleep_before_packet(index, pkt, args.pace_ms)
        ip_id = pkt.ip_id_field if pkt.ip_id_field is not None else (0x1000 + index) & 0xFFFF
        ip = IP(dst=args.dst_ip, id=ip_id)
        if args.src_ip:
            ip.src = args.src_ip
        frame = (
            Ether(src=src_mac, dst=args.dst_mac)
            / ip
            / UDP(sport=args.sport, dport=dport)
            / Raw(_packet_payload(pkt))
        )
        sendp(frame, iface=args.iface, verbose=False)


def main() -> int:
    args = parse_args()
    data = Path(args.input).read_bytes()
    strategy = get_strategy(StrategyID(args.strategy), config=build_strategy_config(args))
    packets = strategy.encode(data, path_id=args.path_id, seq_num=args.seq_num)

    path_counts = {}
    for pkt in packets:
        path_counts[pkt.path_id] = path_counts.get(pkt.path_id, 0) + 1
    print(
        f"strategy={args.strategy} packets={len(packets)} input_bytes={len(data)} "
        f"path_counts={path_counts}"
    )
    if args.dry_run:
        return 0

    dport = args.dport or (50000 + args.strategy)
    if args.send_mode == "socket":
        _send_with_socket(args, packets, dport)
    elif args.send_mode == "scapy":
        _send_with_scapy(args, packets, dport)
    else:
        _send_with_scapy_l2(args, packets, dport)

    print("send_done=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())