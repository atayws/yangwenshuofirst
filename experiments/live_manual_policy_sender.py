"""
手动策略计划 live 发送端。

该脚本把隐蔽数据切成全局 chunk，再按手动策略计划编码为 UDP 承载包。
它只负责发包，不直接修改 P4 路径寄存器；自动化 live 验证脚本会在每个 chunk
发送前切换 s1 的路径模式。
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time
from typing import List

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from experiments.verify_manual_policy_session import (
    MANUAL_LIVE_PLAN,
    encode_chunk,
    load_policy_plan,
    validate_plan,
    weighted_plan,
)
from python.covert_strategies.base import PacketSpec
from python.covert_strategies.session import CovertSessionFramer


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="手动策略计划 live 发送端")
    parser.add_argument("--input", required=True)
    parser.add_argument("--dst-ip", required=True)
    parser.add_argument("--src-ip", default=None)
    parser.add_argument("--iface", default=None)
    parser.add_argument("--src-mac", default=None)
    parser.add_argument("--dst-mac", default="00:00:00:00:00:02")
    parser.add_argument("--sport", type=int, default=41000)
    parser.add_argument("--base-dport", type=int, default=51200)
    parser.add_argument("--chunk-size", type=int, default=4)
    parser.add_argument("--session-id", type=int, default=8)
    parser.add_argument("--chunk-id", type=int, default=None)
    parser.add_argument("--plan-file", default=None)
    parser.add_argument("--pace-ms", type=float, default=1.0)
    parser.add_argument(
        "--send-mode",
        choices=["socket", "scapy-l2"],
        default="scapy-l2",
        help="scapy-l2 可以控制 IPv4 ID，适合策略2/4。",
    )
    parser.add_argument("--summary", default=None)
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def packet_payload(pkt: PacketSpec) -> bytes:
    """根据 PacketSpec 生成实际 UDP payload。"""
    payload = pkt.payload
    if pkt.target_packet_length is not None:
        target_payload_len = max(len(payload), pkt.target_packet_length - 20 - 8)
        if len(payload) < target_payload_len:
            payload += bytes(
                (i * 31 + pkt.fragment_id) & 0xFF
                for i in range(target_payload_len - len(payload))
            )
    return payload


def sleep_before_packet(index: int, pkt: PacketSpec, pace_ms: float) -> None:
    if index <= 0:
        return
    gap_ms = max(float(pkt.send_delay_ms), float(pace_ms))
    if gap_ms > 0:
        time.sleep(gap_ms / 1000.0)


def send_socket(args: argparse.Namespace, packets: List[PacketSpec], dport: int) -> None:
    """普通 UDP socket 发包，不能控制 IP-ID。"""
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if args.src_ip:
        sock.bind((args.src_ip, args.sport))
    else:
        sock.bind(("0.0.0.0", args.sport))
    for index, pkt in enumerate(packets):
        sleep_before_packet(index, pkt, args.pace_ms)
        sock.sendto(packet_payload(pkt), (args.dst_ip, dport))
    sock.close()


def send_scapy_l2(args: argparse.Namespace, packets: List[PacketSpec], dport: int) -> None:
    """二层发包，显式设置 IPv4 ID。"""
    from scapy.all import Ether, IP, UDP, Raw, conf, get_if_hwaddr, sendp

    if not args.iface:
        raise ValueError("scapy-l2 模式必须指定 --iface")
    conf.verb = 0
    src_mac = args.src_mac or get_if_hwaddr(args.iface)
    for index, pkt in enumerate(packets):
        sleep_before_packet(index, pkt, args.pace_ms)
        ip_id = pkt.ip_id_field if pkt.ip_id_field is not None else (0x3000 + index) & 0xFFFF
        ip = IP(dst=args.dst_ip, id=ip_id)
        if args.src_ip:
            ip.src = args.src_ip
        frame = (
            Ether(src=src_mac, dst=args.dst_mac)
            / ip
            / UDP(sport=args.sport, dport=dport)
            / Raw(packet_payload(pkt))
        )
        sendp(frame, iface=args.iface, verbose=False)


def build_chunk_packets(args: argparse.Namespace):
    """按手动计划生成待发送 chunk。"""
    plan = load_policy_plan(args.plan_file, MANUAL_LIVE_PLAN)
    validate_plan(plan)
    secret = Path(args.input).read_bytes()
    chunks = CovertSessionFramer(
        session_id=args.session_id,
        chunk_payload_size=args.chunk_size,
    ).split(secret)
    expanded = weighted_plan(plan)

    selected = []
    for chunk in chunks:
        if args.chunk_id is not None and chunk.chunk_id != args.chunk_id:
            continue
        entry = expanded[chunk.chunk_id % len(expanded)]
        chunk_bytes = chunk.encode()
        sequence_num = 100 + chunk.chunk_id
        packets, _metadata, _config = encode_chunk(chunk_bytes, entry, sequence_num)
        selected.append(
            {
                "chunk": chunk,
                "entry": entry,
                "sequence_num": sequence_num,
                "dport": args.base_dport + chunk.chunk_id,
                "packets": packets,
                "encoded_bytes": len(chunk_bytes),
            }
        )
    return secret, chunks, selected, plan


def main() -> int:
    args = parse_args()
    started = time.time()
    secret, chunks, selected, plan = build_chunk_packets(args)
    sent_packets = 0
    chunk_summaries = []

    for item in selected:
        packets = item["packets"]
        dport = item["dport"]
        entry = item["entry"]
        if not args.dry_run:
            if args.send_mode == "socket":
                send_socket(args, packets, dport)
            else:
                send_scapy_l2(args, packets, dport)
        sent_packets += len(packets)
        chunk_summaries.append(
            {
                "chunk_id": item["chunk"].chunk_id,
                "strategy_id": entry.strategy_id,
                "paths": list(entry.paths),
                "dport": dport,
                "sequence_num": item["sequence_num"],
                "packets": len(packets),
                "encoded_bytes": item["encoded_bytes"],
            }
        )

    summary = {
        "mode": "live_manual_policy_sender",
        "secret_bytes": len(secret),
        "total_chunks": len(chunks),
        "selected_chunks": len(selected),
        "sent_packets": sent_packets,
        "dry_run": bool(args.dry_run),
        "duration_s": round(time.time() - started, 3),
        "manual_live_plan": [
            {
                "name": entry.name,
                "strategy_id": entry.strategy_id,
                "paths": list(entry.paths),
                "weight": entry.weight,
            }
            for entry in plan
        ],
        "chunks": chunk_summaries,
    }
    if args.summary:
        path = Path(args.summary)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if selected else 1


if __name__ == "__main__":
    raise SystemExit(main())
