"""
Live receiver that auto-detects the covert strategy from observed packets.

Unlike live_receive_strategy.py, this entry point does not take --strategy.
The receiver only uses locally configured protocol parameters plus packet
features such as IP-ID, payload tags, packet length, and arrival timing.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Dict, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from python.receiver.strategy_router import StrategyReceiverRouter


def parse_path_weights(raw: str):
    values = [item.strip() for item in raw.split(",") if item.strip()]
    weights = [max(0, int(item)) for item in values[:3]]
    while len(weights) < 3:
        weights.append(0)
    if sum(weights) == 0:
        return [1, 1, 1]
    return weights


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Live auto-detecting covert receiver")
    parser.add_argument("--output-dir", default="experiments/results/live_auto_decoded")
    parser.add_argument("--summary", default="experiments/results/live_auto_receive_summary.json")
    parser.add_argument("--iface", default=None)
    parser.add_argument("--dport", type=int, default=50000)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--expected-packets", type=int, default=0)
    parser.add_argument("--expected-bytes", type=int, default=None)
    parser.add_argument("--sync-key", type=lambda x: int(x, 0), default=0x5A17)
    parser.add_argument("--secret-key", default=None)
    parser.add_argument("--business-payload-len", type=int, default=32)
    parser.add_argument("--strategy4-k", type=int, default=None)
    parser.add_argument("--strategy4-num-output", type=int, default=None)
    parser.add_argument("--path-weights", default=None)
    parser.add_argument(
        "--accept-timing-without-port",
        action="store_true",
        help="Allow timing strategies when captured metadata lacks UDP port data.",
    )
    return parser.parse_args()


def build_common_config(args: argparse.Namespace) -> dict:
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


def build_strategy_configs(args: argparse.Namespace) -> Dict[int, dict]:
    common = build_common_config(args)
    return {strategy_id: dict(common) for strategy_id in range(6)}


def main() -> int:
    args = parse_args()
    output_dir = Path(args.output_dir)
    summary_path = Path(args.summary)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)

    router = StrategyReceiverRouter(
        strategy_configs=build_strategy_configs(args),
        sync_key=int(args.sync_key),
        timing_ports={0: int(args.dport), 1: int(args.dport)},
        accept_timing_without_port=bool(args.accept_timing_without_port),
        allow_explicit_strategy_hint=False,
    )

    from scapy.all import IP, UDP, Raw, sniff

    first_time: Optional[float] = None
    captured = 0

    def handle_packet(packet):
        nonlocal first_time, captured
        if IP not in packet or UDP not in packet:
            return
        if int(packet[UDP].dport) != int(args.dport):
            return
        if first_time is None:
            first_time = float(packet.time)

        payload = bytes(packet[Raw].load) if Raw in packet else b""
        arrival_time_ms = (float(packet.time) - first_time) * 1000.0
        metadata = {
            "arrival_time_ms": arrival_time_ms,
            "ip_id": int(packet[IP].id),
            "packet_length": int(packet[IP].len),
            "payload_length": len(payload),
            "nonce": captured,
            "sport": int(packet[UDP].sport),
            "dport": int(packet[UDP].dport),
            "src_ip": str(packet[IP].src),
            "dst_ip": str(packet[IP].dst),
        }

        router.ingest(payload, metadata)
        captured += 1

    def should_stop(_packet):
        return args.expected_packets > 0 and captured >= args.expected_packets

    sniff(
        iface=args.iface,
        filter=f"udp port {int(args.dport)}",
        prn=handle_packet,
        stop_filter=should_stop,
        timeout=args.timeout,
        store=False,
    )

    results = router.decode_all()
    result_items = []
    success_count = 0
    for result in results:
        if result.decoded is not None:
            output_file = output_dir / f"strategy_{result.strategy_id}_message_{result.message_key}.bin"
            output_file.write_bytes(result.decoded)
            result.output_file = str(output_file)
        if result.success:
            success_count += 1
        result_items.append(result.to_dict())

    summary = {
        "auto_detect": True,
        "dport": int(args.dport),
        "packets_captured": captured,
        "groups_detected": len(results),
        "groups_decoded": success_count,
        "router_summary": router.summary(),
        "ignored_packets": router.ignored_packets[:20],
        "results": result_items,
        "output_dir": str(output_dir),
    }
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if success_count > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
