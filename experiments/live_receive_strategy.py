"""
真实网络单策略接收脚本。

在 Mininet/BMv2 中建议在 h2 上运行。脚本抓取指定 UDP 端口的数据包，调用指定策略解码，
并把结果写入输出文件和摘要文件。策略4只从 IP-ID 中提取喷泉符号，不依赖UDP端口做路径标记。
"""

import argparse
import json
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
    parser = argparse.ArgumentParser(description="真实网络单策略接收端")
    parser.add_argument("--strategy", type=int, required=True, choices=[0, 1, 2, 3, 4, 5])
    parser.add_argument("--output", default="experiments/results/live_decoded.bin")
    parser.add_argument("--summary", default="experiments/results/live_receive_summary.json")
    parser.add_argument("--iface", default=None)
    parser.add_argument("--dport", type=int, default=None)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--expected-packets", type=int, default=0)
    parser.add_argument("--expected-bytes", type=int, default=None)
    parser.add_argument("--sync-key", type=lambda x: int(x, 0), default=0x5A17)
    parser.add_argument("--secret-key", default=None, help="策略2/4等需要加密时使用的字符串密钥")
    parser.add_argument("--business-payload-len", type=int, default=32)
    parser.add_argument("--strategy4-k", type=int, default=None)
    parser.add_argument("--strategy4-num-output", type=int, default=None)
    parser.add_argument("--path-weights", default=None)
    return parser.parse_args()


def build_strategy_config(args: argparse.Namespace) -> dict:
    """根据命令行参数生成策略配置，保证发送端和接收端参数一致。"""
    config = {
        "sync_key": args.sync_key,
        "expected_bytes": args.expected_bytes,
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


def main() -> int:
    args = parse_args()
    strategy = get_strategy(StrategyID(args.strategy), config=build_strategy_config(args))
    dport = args.dport or (50000 + args.strategy)

    from scapy.all import IP, UDP, Raw, sniff

    captured = []
    first_time = None
    strategy2_block_id = 0
    strategy2_last_seq = None

    def handle_packet(packet):
        nonlocal first_time, strategy2_block_id, strategy2_last_seq
        if IP not in packet or UDP not in packet:
            return
        if int(packet[UDP].dport) != dport:
            return
        if first_time is None:
            first_time = float(packet.time)
        payload = bytes(packet[Raw].load) if Raw in packet else b""
        arrival_time_ms = (float(packet.time) - first_time) * 1000.0
        metadata = {
            "arrival_time_ms": arrival_time_ms,
            "ip_id": int(packet[IP].id),
            "packet_length": int(packet[IP].len),
            "nonce": len(captured),
        }
        if args.strategy == 5:
            # 策略5的 IP-ID 只放轻量自描述信息：策略号、路径号和片段低8位。
            parsed_ip_id = strategy.parse_ip_id(int(packet[IP].id)) if hasattr(strategy, "parse_ip_id") else None
            if parsed_ip_id is not None:
                metadata["path_id"] = parsed_ip_id["path_id"]
                metadata["fragment_id"] = parsed_ip_id["fragment_id_mod"]
                metadata["ip_id_info"] = parsed_ip_id
            else:
                # 兼容旧的模拟抓包：源IP第三段可表示路径。
                try:
                    src_octets = str(packet[IP].src).split(".")
                    inferred_path = int(src_octets[2]) - 1
                    if 0 <= inferred_path <= 2:
                        metadata["path_id"] = inferred_path
                except (IndexError, ValueError):
                    pass
                metadata["fragment_id"] = len(captured)
        if args.strategy == 2:
            ip_id = int(packet[IP].id)
            seq_mod = (ip_id >> 8) & 0x0F
            if strategy2_last_seq is not None and seq_mod < strategy2_last_seq:
                strategy2_block_id += 1
            metadata["fragment_id"] = strategy2_block_id * 16 + seq_mod
            metadata["block_id"] = strategy2_block_id
            metadata["seq_mod"] = seq_mod
            metadata["cipher_value"] = ip_id & 0xFF
            strategy2_last_seq = seq_mod
        captured.append({"payload": payload, "metadata": metadata})

    def should_stop(_packet):
        return args.expected_packets > 0 and len(captured) >= args.expected_packets

    sniff(
        iface=args.iface,
        filter=f"udp port {dport}",
        prn=handle_packet,
        stop_filter=should_stop,
        timeout=args.timeout,
        store=False,
    )

    payloads = [item["payload"] for item in captured]
    metadata = [item["metadata"] for item in captured]
    decoded = strategy.decode(payloads, metadata)

    output_path = Path(args.output)
    summary_path = Path(args.summary)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)

    if decoded is not None:
        output_path.write_bytes(decoded)

    ip_ids = [item["metadata"].get("ip_id") for item in captured[:12]]
    summary = {
        "strategy_id": args.strategy,
        "dport": dport,
        "packets_received": len(captured),
        "decoded_bytes": len(decoded) if decoded is not None else 0,
        "output_file": str(output_path),
        "success": decoded is not None,
        "ip_id_sample_hex": [hex(int(value)) for value in ip_ids if value is not None],
        "decode_info": getattr(strategy, "last_decode_info", {}),
    }
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if decoded is not None else 1


if __name__ == "__main__":
    raise SystemExit(main())