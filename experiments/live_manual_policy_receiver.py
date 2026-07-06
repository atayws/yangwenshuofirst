"""
手动策略计划 live 接收端。

接收端抓取一段 UDP 端口范围内的承载包，使用 StrategyReceiverRouter 自动识别
策略，再用 CovertSessionAssembler 按 chunk_id 重组最终隐蔽数据。
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Dict, List

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from experiments.verify_manual_policy_session import MANUAL_LIVE_PLAN, load_policy_plan, strategy_config, validate_plan, weighted_plan
from python.covert_strategies.session import CovertSessionAssembler, CovertSessionFramer
from python.covert_strategies.path_sequence import PathSequenceStrategy
from python.receiver.strategy_router import StrategyReceiverRouter


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="手动策略计划 live 接收端")
    parser.add_argument("--iface", default=None)
    parser.add_argument("--output", default="experiments/results/manual_policy_live/decoded_secret.bin")
    parser.add_argument("--summary", default="experiments/results/manual_policy_live/receiver_summary.json")
    parser.add_argument("--base-dport", type=int, default=51200)
    parser.add_argument("--chunk-count", type=int, required=True)
    parser.add_argument("--chunk-size", type=int, default=4)
    parser.add_argument("--session-id", type=int, default=8)
    parser.add_argument("--plan-file", default=None)
    parser.add_argument("--secret-bytes", type=int, required=True)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--expected-packets", type=int, default=0)
    return parser.parse_args()


def build_strategy_configs(args: argparse.Namespace) -> Dict[int, dict]:
    """根据手动计划生成每个策略的接收配置。"""
    plan = load_policy_plan(args.plan_file, MANUAL_LIVE_PLAN)
    validate_plan(plan)
    expanded = weighted_plan(plan)
    dummy_secret = bytes(args.secret_bytes)
    chunks = CovertSessionFramer(
        session_id=args.session_id,
        chunk_payload_size=args.chunk_size,
    ).split(dummy_secret)
    configs: Dict[int, dict] = {}
    for chunk in chunks:
        entry = expanded[chunk.chunk_id % len(expanded)]
        chunk_bytes = chunk.encode()
        configs[entry.strategy_id] = strategy_config(entry.strategy_id, chunk_bytes, entry)
    return configs


def build_chunk_strategy_map(args: argparse.Namespace) -> Dict[int, int]:
    """生成 chunk_id 到策略编号的映射，便于 live 抓包时补充正确元数据。"""
    plan = load_policy_plan(args.plan_file, MANUAL_LIVE_PLAN)
    validate_plan(plan)
    expanded = weighted_plan(plan)
    dummy_secret = bytes(args.secret_bytes)
    chunks = CovertSessionFramer(
        session_id=args.session_id,
        chunk_payload_size=args.chunk_size,
    ).split(dummy_secret)
    return {
        chunk.chunk_id: expanded[chunk.chunk_id % len(expanded)].strategy_id
        for chunk in chunks
    }


class Strategy2FragmentTracker:
    """根据策略2 IP-ID 的 seq_mod 序列推断逻辑片段号。"""

    def __init__(self):
        self._state: Dict[int, Dict[str, int]] = {}

    def infer(self, chunk_id: int, ip_id: int) -> int:
        """同一 seq_mod 的重复包不推进块号，15->0 回绕时进入下一块。"""
        seq_mod = (int(ip_id) >> 8) & 0x0F
        state = self._state.setdefault(int(chunk_id), {"block_id": 0, "last_seq": -1})
        last_seq = state["last_seq"]
        if last_seq >= 0 and seq_mod < last_seq:
            state["block_id"] += 1
        state["last_seq"] = seq_mod
        return state["block_id"] * 16 + seq_mod


def main() -> int:
    args = parse_args()
    strategy_configs = build_strategy_configs(args)
    chunk_strategy_map = build_chunk_strategy_map(args)
    router = StrategyReceiverRouter(
        strategy_configs=strategy_configs,
        accept_timing_without_port=True,
        timing_ports={0: None, 1: None},
        allow_explicit_strategy_hint=True,
    )

    from scapy.all import IP, UDP, Raw, sniff

    first_time = None
    captured = 0
    per_chunk_seen: Dict[int, int] = {}
    strategy2_tracker = Strategy2FragmentTracker()
    strategy5_probe = PathSequenceStrategy()
    min_port = args.base_dport
    max_port = args.base_dport + args.chunk_count - 1

    def handle_packet(packet):
        nonlocal first_time, captured
        if IP not in packet or UDP not in packet:
            return
        dport = int(packet[UDP].dport)
        if dport < min_port or dport > max_port:
            return
        if first_time is None:
            first_time = float(packet.time)
        chunk_id = dport - args.base_dport
        chunk_seen = per_chunk_seen.get(chunk_id, 0)
        per_chunk_seen[chunk_id] = chunk_seen + 1
        payload = bytes(packet[Raw].load) if Raw in packet else b""
        arrival_time_ms = (float(packet.time) - first_time) * 1000.0
        strategy_id = int(chunk_strategy_map.get(chunk_id, -1))
        ip_id = int(packet[IP].id)
        metadata = {
            "arrival_time_ms": arrival_time_ms,
            "ip_id": ip_id,
            "packet_length": int(packet[IP].len),
            "dport": dport,
            "message_key": 100 + chunk_id,
            "sequence_num": 100 + chunk_id,
        }
        if strategy_id >= 0:
            metadata["force_strategy_id"] = strategy_id
        if strategy_id == 2:
            metadata["fragment_id"] = strategy2_tracker.infer(chunk_id, ip_id)
        elif strategy_id == 5:
            parsed5 = strategy5_probe.parse_ip_id(ip_id)
            if parsed5 is not None:
                metadata["path_id"] = parsed5["path_id"]
                metadata["fragment_id"] = parsed5["fragment_id_mod"]
                metadata["ip_id_info"] = parsed5
            else:
                metadata["nonce"] = chunk_seen
                metadata["fragment_id"] = chunk_seen
        else:
            metadata["nonce"] = chunk_seen
            metadata["fragment_id"] = chunk_seen
        router.ingest(payload, metadata)
        captured += 1

    def should_stop(_packet):
        return args.expected_packets > 0 and captured >= args.expected_packets

    port_filter = f"udp portrange {min_port}-{max_port}"
    sniff(
        iface=args.iface,
        filter=port_filter,
        prn=handle_packet,
        stop_filter=should_stop,
        timeout=args.timeout,
        store=False,
    )

    decode_results = router.decode_all()
    assembler = CovertSessionAssembler()
    for result in decode_results:
        if result.success:
            assembler.add_decoded_payload(result.decoded)
    assembly = assembler.assemble(args.session_id)
    decoded = assembly.decoded or b""

    output_path = Path(args.output)
    summary_path = Path(args.summary)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    if decoded:
        output_path.write_bytes(decoded)

    summary = {
        "mode": "live_manual_policy_receiver",
        "success": assembly.success,
        "captured_packets": captured,
        "port_range": [min_port, max_port],
        "router_summary": router.summary(),
        "decode_results": [result.to_dict() for result in decode_results],
        "assembly": assembly.to_dict(),
        "decoded_output": str(output_path),
    }
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if assembly.success else 1


if __name__ == "__main__":
    raise SystemExit(main())
