"""
手动策略计划下的全局隐蔽会话闭环验证。

中期阶段先不用 PPO。该脚本用一个手动计划把全局 chunk 分配给不同链路和策略：
- 单路径策略：0/1/2/3/5 可以绑定到某一条 path；
- 多路径策略：4 必须绑定至少两条 path，体现喷泉码多路径协同。

接收端流程为：统一分发器识别策略 -> 各策略 decode -> 全局 session 重组。
"""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
import json
from pathlib import Path
import random
import sys
from typing import Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from experiments.verify_transmission import build_decode_inputs
from python.covert_strategies.base import PacketSpec, StrategyID
from python.covert_strategies.session import CovertSessionAssembler, CovertSessionFramer
from python.covert_strategies.strategy_registry import get_strategy
from python.receiver.strategy_router import StrategyReceiverRouter


DEFAULT_SECRET = (
    b"MIDTERM_MANUAL_POLICY_SESSION:"
    b"path0_strategy0,path1_strategy2,path01_strategy4,path2_strategy3."
)


@dataclass(frozen=True)
class PolicyEntry:
    """手动策略计划中的一项。"""

    name: str
    strategy_id: int
    paths: Tuple[int, ...]
    weight: int = 1

    def to_dict(self) -> dict:
        """转换为可写入 JSON 的字典。"""
        return {
            "name": self.name,
            "strategy_id": int(self.strategy_id),
            "paths": [int(path) for path in self.paths],
            "weight": int(self.weight),
        }


DEFAULT_PLAN = [
    PolicyEntry("path0_timing_s0", 0, (0,), 1),
    PolicyEntry("path1_ipid_s2", 2, (1,), 1),
    PolicyEntry("path01_fountain_s4", 4, (0, 1), 1),
    PolicyEntry("path2_length_s3", 3, (2,), 1),
]


MANUAL_LIVE_PLAN = [
    PolicyEntry("path0_ipid_s2", 2, (0,), 1),
    PolicyEntry("path2_length_s3", 3, (2,), 1),
    PolicyEntry("path01_fountain_s4", 4, (0, 1), 1),
]


def policy_entry_from_dict(raw: dict) -> PolicyEntry:
    """从 JSON 字典恢复策略计划项。"""
    return PolicyEntry(
        name=str(raw["name"]),
        strategy_id=int(raw["strategy_id"]),
        paths=tuple(int(path) for path in raw["paths"]),
        weight=int(raw.get("weight", 1)),
    )


def load_policy_plan(path: Optional[str], default_plan: List[PolicyEntry]) -> List[PolicyEntry]:
    """读取策略计划文件；没有文件时使用默认计划。"""
    if not path:
        return list(default_plan)
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    entries = raw.get("entries", raw) if isinstance(raw, dict) else raw
    plan = [policy_entry_from_dict(item) for item in entries]
    validate_plan(plan)
    return plan


def write_policy_plan(path: Path, plan: List[PolicyEntry], extra: Optional[dict] = None) -> None:
    """把策略计划写入 JSON，便于 live 发送端和接收端共享。"""
    validate_plan(plan)
    data = {
        "entries": [entry.to_dict() for entry in plan],
    }
    if extra:
        data.update(extra)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="验证手动策略计划的全局会话闭环")
    parser.add_argument("--output-dir", default="experiments/results/manual_policy")
    parser.add_argument("--secret", default=None, help="要发送的隐蔽明文字符串")
    parser.add_argument("--chunk-size", type=int, default=8)
    parser.add_argument("--session-id", type=int, default=7)
    parser.add_argument("--seed", type=int, default=20260626)
    parser.add_argument("--noise-packets", type=int, default=18)
    return parser.parse_args()


def validate_plan(plan: List[PolicyEntry]) -> None:
    """检查手动计划是否合法，尤其是策略4必须多路径协同。"""
    if not plan:
        raise ValueError("手动策略计划不能为空")
    for entry in plan:
        if entry.strategy_id < 0 or entry.strategy_id > 5:
            raise ValueError(f"{entry.name}: strategy_id 非法")
        if not entry.paths:
            raise ValueError(f"{entry.name}: paths 不能为空")
        for path in entry.paths:
            if path < 0 or path > 2:
                raise ValueError(f"{entry.name}: path 只能是0/1/2")
        if entry.strategy_id == 4 and len(set(entry.paths)) < 2:
            raise ValueError("策略4是多路径喷泉码协同策略，至少需要绑定两条路径")


def strategy_config(strategy_id: int, chunk_bytes: bytes, entry: PolicyEntry) -> dict:
    """生成发送端和接收端共用的策略参数。"""
    config = {
        "expected_bytes": len(chunk_bytes),
        "business_payload_len": 32,
    }
    if strategy_id == 0:
        config.update({
            "short_gap_ms": 20,
            "long_gap_ms": 80,
            "min_relation_delta_ms": 12,
        })
    if strategy_id == 1:
        config.update({
            "rank_gaps_ms": [20, 60, 110],
            "min_rank_delta_ms": 12,
        })
    if strategy_id == 4:
        weights = [0, 0, 0]
        for path in entry.paths:
            weights[path] = 1
        config.update({"k": 8, "num_output": 16, "path_weights": weights})
    return config


def weighted_plan(plan: List[PolicyEntry]) -> List[PolicyEntry]:
    """按 weight 展开计划，便于轮流给 chunk 分配策略。"""
    expanded: List[PolicyEntry] = []
    for entry in plan:
        expanded.extend([entry] * max(1, int(entry.weight)))
    return expanded


def encode_chunk(
    chunk_bytes: bytes,
    entry: PolicyEntry,
    sequence_num: int,
) -> Tuple[List[PacketSpec], List[dict], dict]:
    """用计划中的某个策略编码一个全局 chunk。"""
    strategy = get_strategy(
        StrategyID(entry.strategy_id),
        config=strategy_config(entry.strategy_id, chunk_bytes, entry),
    )
    path_id = entry.paths[0]
    packets = strategy.encode(chunk_bytes, path_id=path_id, seq_num=sequence_num)

    if entry.strategy_id == 4:
        allowed = set(entry.paths)
        for pkt in packets:
            if pkt.path_id not in allowed:
                pkt.path_id = entry.paths[pkt.fragment_id % len(entry.paths)]
    else:
        for pkt in packets:
            pkt.path_id = path_id

    _payloads, metadata = build_decode_inputs(packets)
    config = strategy_config(entry.strategy_id, chunk_bytes, entry)
    for meta in metadata:
        meta["message_key"] = sequence_num
        meta["sequence_num"] = sequence_num
        meta["policy_entry"] = entry.name
        meta["expected_bytes"] = len(chunk_bytes)
        meta["business_payload_len"] = 32
        meta["dport"] = 50000 + entry.strategy_id
        meta.update({key: value for key, value in config.items() if key not in meta})
    return packets, metadata, config


def build_noise_packets(count: int) -> List[dict]:
    """普通业务噪声包，接收分发器应当忽略。"""
    records = []
    for index in range(count):
        payload = f"normal-udp-business-{index:03d}".encode("ascii")
        records.append(
            {
                "kind": "noise",
                "payload": payload,
                "metadata": {
                    "ip_id": 0x2000 + index,
                    "packet_length": len(payload) + 40,
                    "arrival_time_ms": float(index),
                    "dport": 5201,
                    "path_id": index % 3,
                },
                "plan": None,
            }
        )
    return records


def build_records(
    secret: bytes,
    plan: List[PolicyEntry],
    chunk_size: int,
    session_id: int,
    noise_packets: int,
    seed: int,
) -> Tuple[List[dict], Dict[int, bytes], Dict[int, dict], List[dict]]:
    """生成混合承载记录和预期 chunk 数据。"""
    validate_plan(plan)
    framer = CovertSessionFramer(session_id=session_id, chunk_payload_size=chunk_size)
    chunks = framer.split(secret)
    expanded_plan = weighted_plan(plan)
    records: List[dict] = []
    expected_chunks: Dict[int, bytes] = {}
    strategy_configs: Dict[int, dict] = {}
    assignment_rows: List[dict] = []

    for chunk in chunks:
        entry = expanded_plan[chunk.chunk_id % len(expanded_plan)]
        chunk_bytes = chunk.encode()
        sequence_num = 100 + chunk.chunk_id
        packets, metadata, config = encode_chunk(chunk_bytes, entry, sequence_num)
        strategy_configs[entry.strategy_id] = config
        expected_chunks[chunk.chunk_id] = chunk.payload
        assignment_rows.append(
            {
                "chunk_id": chunk.chunk_id,
                "total_chunks": chunk.total_chunks,
                "strategy_id": entry.strategy_id,
                "policy_entry": entry.name,
                "paths": ",".join(str(path) for path in entry.paths),
                "sequence_num": sequence_num,
                "encoded_packets": len(packets),
                "chunk_payload_hex": chunk.payload.hex(),
            }
        )
        for pkt, meta in zip(packets, metadata):
            records.append(
                {
                    "kind": "covert",
                    "payload": pkt.payload,
                    "metadata": meta,
                    "plan": entry,
                    "chunk_id": chunk.chunk_id,
                    "strategy_id": entry.strategy_id,
                }
            )

    records.extend(build_noise_packets(noise_packets))
    rng = random.Random(seed)
    rng.shuffle(records)
    return records, expected_chunks, strategy_configs, assignment_rows


def decode_session(records: List[dict], strategy_configs: Dict[int, dict]) -> Tuple[dict, bytes]:
    """使用统一分发器和全局重组器恢复隐蔽数据。"""
    router = StrategyReceiverRouter(strategy_configs=strategy_configs)
    for record in records:
        router.ingest(record["payload"], record["metadata"])

    decode_results = router.decode_all()
    assembler = CovertSessionAssembler()
    for result in decode_results:
        if result.success:
            assembler.add_decoded_payload(result.decoded)
    assembly = assembler.assemble()
    decoded = assembly.decoded or b""

    summary = {
        "success": assembly.success,
        "router_summary": router.summary(),
        "decode_results": [result.to_dict() for result in decode_results],
        "assembly": assembly.to_dict(),
    }
    return summary, decoded


def write_assignment_csv(path: Path, rows: List[dict]) -> None:
    """写出每个 chunk 的策略与路径分配。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "chunk_id",
        "total_chunks",
        "strategy_id",
        "policy_entry",
        "paths",
        "sequence_num",
        "encoded_packets",
        "chunk_payload_hex",
    ]
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    secret = args.secret.encode("utf-8") if args.secret is not None else DEFAULT_SECRET
    records, expected_chunks, strategy_configs, assignments = build_records(
        secret=secret,
        plan=DEFAULT_PLAN,
        chunk_size=args.chunk_size,
        session_id=args.session_id,
        noise_packets=args.noise_packets,
        seed=args.seed,
    )
    summary, decoded = decode_session(records, strategy_configs)
    hidden_match = decoded == secret
    summary.update(
        {
            "hidden_match": hidden_match,
            "secret_bytes": len(secret),
            "decoded_bytes": len(decoded),
            "chunk_count": len(expected_chunks),
            "manual_plan": [
                {
                    "name": entry.name,
                    "strategy_id": entry.strategy_id,
                    "paths": list(entry.paths),
                    "weight": entry.weight,
                }
                for entry in DEFAULT_PLAN
            ],
        }
    )
    summary["success"] = bool(summary["success"] and hidden_match)

    (output_dir / "input_secret.bin").write_bytes(secret)
    (output_dir / "decoded_secret.bin").write_bytes(decoded)
    (output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    write_assignment_csv(output_dir / "chunk_assignments.csv", assignments)

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"chunk分配: {output_dir / 'chunk_assignments.csv'}")
    print(f"解码输出: {output_dir / 'decoded_secret.bin'}")
    return 0 if summary["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
