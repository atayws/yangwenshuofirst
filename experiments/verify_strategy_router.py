"""
统一接收分发器离线验证脚本。

该脚本生成六种隐蔽策略的承载包，并混入普通业务噪声包，模拟接收端抓包后由
StrategyReceiverRouter 自动识别、分流和解码。它验证的是“接收端闭环框架”，
不替代 Mininet live 测试。
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import random
import sys
from typing import Dict, List, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from experiments.verify_transmission import build_decode_inputs
from python.covert_strategies.base import PacketSpec, StrategyID
from python.covert_strategies.strategy_registry import get_strategy
from python.receiver.strategy_router import StrategyReceiverRouter


DEFAULT_MESSAGES = {
    0: b"S0_ROUTER_OK",
    1: b"S1_ROUTER_OK",
    2: b"S2_ROUTER_OK",
    3: b"S3_ROUTER_OK",
    4: b"S4_ROUTER_OK",
    5: b"S5_ROUTER_OK",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="验证统一策略接收分发器")
    parser.add_argument(
        "--output-dir",
        default="experiments/results",
        help="结果输出目录",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=20260626,
        help="混合流随机种子",
    )
    parser.add_argument(
        "--noise-packets",
        type=int,
        default=24,
        help="混入的普通业务噪声包数量",
    )
    return parser.parse_args()


def strategy_config(strategy_id: int, message: bytes) -> dict:
    """为验证脚本生成和接收端保持一致的策略参数。"""
    base = {
        "expected_bytes": len(message),
        "business_payload_len": 32,
    }
    if strategy_id == 4:
        base.update({"k": 8, "num_output": 16, "path_weights": [1, 1, 1]})
    return base


def build_strategy_packets(
    strategy_id: int,
    message: bytes,
    seq_num: int,
) -> Tuple[List[PacketSpec], List[dict]]:
    """调用策略 encode() 并转换成分发器需要的元数据。"""
    strategy = get_strategy(
        StrategyID(strategy_id),
        config=strategy_config(strategy_id, message),
    )
    packets = strategy.encode(message, path_id=strategy_id % 3, seq_num=seq_num)
    _payloads, metadata = build_decode_inputs(packets)

    for item in metadata:
        item["message_key"] = seq_num
        item["expected_bytes"] = len(message)
        item["business_payload_len"] = 32
        if strategy_id == 0:
            item["dport"] = 50000
        elif strategy_id == 1:
            item["dport"] = 50001
        else:
            item["dport"] = 50000 + strategy_id
        if strategy_id == 4:
            item["k"] = 8
            item["num_output"] = 16
            item["path_weights"] = [1, 1, 1]
    return packets, metadata


def build_noise_packets(count: int) -> List[Tuple[bytes, dict]]:
    """生成普通业务噪声包，分发器应该忽略这些包。"""
    noise = []
    for index in range(count):
        payload = f"normal-business-payload-{index:03d}".encode("ascii")
        metadata = {
            "ip_id": 0x1000 + index,
            "packet_length": len(payload) + 40,
            "dport": 5201,
            "arrival_time_ms": float(index),
            "path_id": index % 3,
        }
        noise.append((payload, metadata))
    return noise


def build_mixed_stream(seed: int, noise_packets: int) -> Tuple[List[dict], Dict[int, bytes]]:
    """
    生成混合流。

    时序策略0/1的解码依赖各自承载包之间的相对 arrival_time_ms，因此即使包级记录
    被打乱，元数据中的时间戳仍保持原策略内部的发送计划。
    """
    records: List[dict] = []
    expected_messages = dict(DEFAULT_MESSAGES)

    for strategy_id, message in expected_messages.items():
        seq_num = strategy_id + 1
        packets, metadata = build_strategy_packets(strategy_id, message, seq_num)
        for pkt, meta in zip(packets, metadata):
            records.append(
                {
                    "kind": "covert",
                    "strategy_id": strategy_id,
                    "payload": pkt.payload,
                    "metadata": meta,
                }
            )

    for payload, metadata in build_noise_packets(noise_packets):
        records.append(
            {
                "kind": "noise",
                "strategy_id": None,
                "payload": payload,
                "metadata": metadata,
            }
        )

    rng = random.Random(seed)
    rng.shuffle(records)
    return records, expected_messages


def write_trace(trace_path: Path, records: List[dict], router: StrategyReceiverRouter) -> None:
    """写出混合流分发轨迹，方便检查每个包被如何识别。"""
    trace_path.parent.mkdir(parents=True, exist_ok=True)
    routed_by_arrival = {
        item.arrival_index: item
        for packets in router.buffers.values()
        for item in packets
    }
    fieldnames = [
        "stream_index",
        "kind",
        "expected_strategy",
        "routed_strategy",
        "message_key",
        "route_reason",
        "ip_id_hex",
        "dport",
        "packet_length",
        "arrival_time_ms",
    ]
    with trace_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for stream_index, record in enumerate(records, start=1):
            routed = routed_by_arrival.get(stream_index)
            meta = record["metadata"]
            ip_id = meta.get("ip_id")
            writer.writerow(
                {
                    "stream_index": stream_index,
                    "kind": record["kind"],
                    "expected_strategy": "" if record["strategy_id"] is None else record["strategy_id"],
                    "routed_strategy": "" if routed is None else routed.strategy_id,
                    "message_key": "" if routed is None else routed.message_key,
                    "route_reason": "" if routed is None else routed.reason,
                    "ip_id_hex": "" if ip_id is None else f"0x{int(ip_id) & 0xffff:04x}",
                    "dport": meta.get("dport", ""),
                    "packet_length": meta.get("packet_length", ""),
                    "arrival_time_ms": meta.get("arrival_time_ms", ""),
                }
            )


def main() -> int:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    records, expected_messages = build_mixed_stream(args.seed, args.noise_packets)
    router = StrategyReceiverRouter(
        strategy_configs={
            sid: strategy_config(sid, message)
            for sid, message in expected_messages.items()
        }
    )

    for record in records:
        router.ingest(record["payload"], record["metadata"])

    results = router.decode_all()
    decoded_dir = output_dir / "router_decoded"
    decoded_dir.mkdir(parents=True, exist_ok=True)

    result_items = []
    all_success = True
    for result in results:
        expected = expected_messages.get(result.strategy_id)
        match = result.decoded == expected
        all_success = all_success and result.success and match
        output_file = decoded_dir / f"strategy_{result.strategy_id}_message_{result.message_key}.bin"
        if result.decoded is not None:
            output_file.write_bytes(result.decoded)
            result.output_file = str(output_file)
        item = result.to_dict()
        item["expected_hex"] = expected.hex() if expected is not None else None
        item["decoded_hex"] = result.decoded.hex() if result.decoded is not None else None
        item["match_expected"] = match
        result_items.append(item)

    summary = {
        "success": all_success and len(results) == len(expected_messages),
        "seed": args.seed,
        "noise_packets": args.noise_packets,
        "router_summary": router.summary(),
        "results": result_items,
    }

    summary_path = output_dir / "router_summary.json"
    trace_path = output_dir / "router_trace.csv"
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    write_trace(trace_path, records, router)

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"分发轨迹: {trace_path}")
    print(f"解码输出: {decoded_dir}")
    return 0 if summary["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
