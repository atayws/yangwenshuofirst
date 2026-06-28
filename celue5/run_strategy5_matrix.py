#!/usr/bin/env python3
"""
策略5离线矩阵验证。

策略5用三条路径的排列顺序承载隐蔽比特，真实 live 化需要接收端能获得每个包的实际路径。
本脚本先在策略库层模拟 path_id 元数据，验证编码、乱序、缺包和错误路径排列下的解码表现。
"""

import csv
import json
import random
import sys
from pathlib import Path
from typing import Callable, List, Tuple

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from python.covert_strategies.base import StrategyID
from python.covert_strategies.path_sequence import DEFAULT_SYMBOL_MAP, PathSequenceStrategy
from python.covert_strategies.strategy_registry import get_strategy

CELUE_DIR = ROOT / "celue5"
RESULTS_DIR = CELUE_DIR / "results"
INPUT_BITS = CELUE_DIR / "input_bits.txt"
INPUT_PAYLOAD = CELUE_DIR / "input_payload.bin"
DECODED_OUTPUT = CELUE_DIR / "decoded_output.bin"
SUMMARY_JSON = RESULTS_DIR / "summary.json"
SUMMARY_CSV = RESULTS_DIR / "summary.csv"

RANDOM_SEED = 20260626
BIT_COUNT = 100
HEADER_WINDOWS = 8 * 4


def bits_to_bytes(bits: str) -> bytes:
    """把二进制字符串按 8 bit 一组转成字节，不足 8 bit 的末尾补 0。"""
    padded = bits + "0" * ((8 - len(bits) % 8) % 8)
    return bytes(int(padded[i:i + 8], 2) for i in range(0, len(padded), 8))


def bytes_to_bits(data: bytes, bit_count: int) -> str:
    """把字节转回二进制字符串，并裁剪到原始 bit 长度。"""
    return "".join(f"{byte:08b}" for byte in data)[:bit_count]


def make_input() -> Tuple[str, bytes]:
    """生成固定随机种子的 100 bit 隐蔽数据，保证每次测试可复现。"""
    rng = random.Random(RANDOM_SEED)
    bits = "".join(str(rng.randint(0, 1)) for _ in range(BIT_COUNT))
    payload = bits_to_bytes(bits)
    CELUE_DIR.mkdir(parents=True, exist_ok=True)
    INPUT_BITS.write_text(bits + "\n", encoding="utf-8")
    INPUT_PAYLOAD.write_bytes(payload)
    return bits, payload


def base_pairs(strategy: PathSequenceStrategy, payload: bytes):
    """生成原始包列表和解码所需的 path_id/fragment_id 元数据。"""
    packets = strategy.encode(payload, path_id=0, seq_num=5)
    pairs = []
    for pkt in packets:
        pairs.append({
            "payload": pkt.payload,
            "metadata": {
                "path_id": pkt.path_id,
                "fragment_id": pkt.fragment_id,
                "strategy_id": pkt.strategy_id,
            },
        })
    return packets, pairs


def window_sequence(pairs, window_id: int):
    """读取某个三包窗口的路径排列。"""
    start = window_id * 3
    if start + 2 >= len(pairs):
        return None
    return tuple(int(pairs[start + offset]["metadata"]["path_id"]) for offset in range(3))


def find_nonzero_data_windows(pairs, count: int) -> List[int]:
    """找出数据区中符号不为 00 的窗口，便于缺包后能观察到局部误码。"""
    zero_sequence = DEFAULT_SYMBOL_MAP[0]
    found: List[int] = []
    for window_id in range(HEADER_WINDOWS, len(pairs) // 3):
        if window_sequence(pairs, window_id) != zero_sequence:
            found.append(window_id)
            if len(found) >= count:
                break
    if len(found) < count:
        raise RuntimeError("没有找到足够的数据区非零路径窗口")
    return found


def drop_fragment_ids(pairs, fragment_ids: List[int]):
    """按 fragment_id 删除部分承载包，模拟链路丢包。"""
    drop_set = set(fragment_ids)
    return [item for item in pairs if int(item["metadata"]["fragment_id"]) not in drop_set]


def decode_case(strategy: PathSequenceStrategy, pairs, input_bits: str, input_payload: bytes) -> dict:
    """执行解码并统计 bit 级匹配情况。"""
    payloads = [item["payload"] for item in pairs]
    metadata = [item["metadata"] for item in pairs]
    decoded = strategy.decode(payloads, metadata)
    decode_info = getattr(strategy, "last_decode_info", {})

    if decoded is None:
        decoded_bits = ""
        bit_matches = 0
        ratio = 0.0
    else:
        decoded_bits = bytes_to_bits(decoded, BIT_COUNT)
        compare_len = min(len(input_bits), len(decoded_bits))
        bit_matches = sum(1 for i in range(compare_len) if input_bits[i] == decoded_bits[i])
        ratio = bit_matches / len(input_bits) if input_bits else 1.0

    result = {
        "decoded": decoded,
        "decoded_bits": decoded_bits,
        "decode_success": decoded is not None,
        "complete": bool(decode_info.get("complete")),
        "exact_match": decoded == input_payload,
        "bit_matches": bit_matches,
        "bit_total": len(input_bits),
        "bit_match_ratio": round(ratio, 4),
        "decode_info": decode_info,
    }
    return result


def case_clean(pairs):
    """无丢包、无乱序。"""
    return list(pairs), {"reordered": False, "dropped_fragments": [], "tampered_windows": []}


def case_reordered(pairs):
    """打乱接收顺序，依靠 fragment_id 重组。"""
    rng = random.Random(RANDOM_SEED + 1)
    output = list(pairs)
    rng.shuffle(output)
    return output, {"reordered": True, "dropped_fragments": [], "tampered_windows": []}


def case_one_data_loss(pairs):
    """数据区丢 1 个包，观察是否只造成局部 unknown。"""
    window = find_nonzero_data_windows(pairs, 1)[0]
    fragment_id = window * 3 + 1
    return drop_fragment_ids(pairs, [fragment_id]), {
        "reordered": False,
        "dropped_fragments": [fragment_id],
        "tampered_windows": [],
    }


def case_sparse_data_loss(pairs):
    """数据区稀疏丢 3 个包，验证后续窗口不会整体错位。"""
    windows = find_nonzero_data_windows(pairs, 3)
    dropped = [window * 3 + (index % 3) for index, window in enumerate(windows)]
    return drop_fragment_ids(pairs, dropped), {
        "reordered": False,
        "dropped_fragments": dropped,
        "tampered_windows": [],
    }


def case_invalid_permutation(pairs):
    """把一个数据窗口改成重复路径，模拟路径观测错误或异常调度。"""
    output = [
        {"payload": item["payload"], "metadata": dict(item["metadata"])}
        for item in pairs
    ]
    window = find_nonzero_data_windows(output, 1)[0]
    start = window * 3
    output[start + 2]["metadata"]["path_id"] = output[start + 1]["metadata"]["path_id"]
    return output, {
        "reordered": False,
        "dropped_fragments": [],
        "tampered_windows": [window],
    }


def case_header_loss(pairs):
    """帧头区丢 1 个包，验证当前方案的边界。"""
    return drop_fragment_ids(pairs, [1]), {
        "reordered": False,
        "dropped_fragments": [1],
        "tampered_windows": [],
    }


CASES: List[Tuple[str, str, Callable]] = [
    ("clean_ordered", "理想顺序接收，验证基本编解码。", case_clean),
    ("reordered_by_fragment", "全局乱序接收，依靠 fragment_id 恢复窗口顺序。", case_reordered),
    ("one_data_packet_loss", "数据区丢 1 个承载包，应只标记局部 unknown，不让后续错位。", case_one_data_loss),
    ("sparse_data_packet_loss", "数据区稀疏丢 3 个承载包，验证局部误码不会扩散。", case_sparse_data_loss),
    ("invalid_data_permutation", "一个数据窗口路径排列异常，应产生局部 unknown。", case_invalid_permutation),
    ("header_packet_loss", "帧头区丢包，当前方案应拒绝输出完整明文。", case_header_loss),
]


def write_case_artifacts(case_dir: Path, result: dict, input_bits: str) -> None:
    """写出单个 case 的明文、解码结果和 JSON 摘要。"""
    case_dir.mkdir(parents=True, exist_ok=True)
    if result["decoded"] is not None:
        (case_dir / "decoded_output.bin").write_bytes(result["decoded"])
        (case_dir / "decoded_bits.txt").write_text(result["decoded_bits"] + "\n", encoding="utf-8")
    else:
        (case_dir / "decoded_bits.txt").write_text("<DECODE_FAILED>\n", encoding="utf-8")
    (case_dir / "input_bits.txt").write_text(input_bits + "\n", encoding="utf-8")


def main() -> int:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    input_bits, input_payload = make_input()
    strategy = get_strategy(StrategyID.PATH_SEQUENCE)
    if not isinstance(strategy, PathSequenceStrategy):
        raise RuntimeError("策略5注册表返回了非 PathSequenceStrategy 实例")

    packets, pairs = base_pairs(strategy, input_payload)
    results = []
    for name, note, mutator in CASES:
        case_strategy = get_strategy(StrategyID.PATH_SEQUENCE)
        mutated_pairs, mutation = mutator(pairs)
        decoded_info = decode_case(case_strategy, mutated_pairs, input_bits, input_payload)
        decoded = decoded_info.pop("decoded")
        result = {
            "case": name,
            "note": note,
            "input_bits": input_bits,
            "input_bytes": len(input_payload),
            "expected_packets": len(packets),
            "received_packets": len(mutated_pairs),
            "packet_loss_count": len(packets) - len(mutated_pairs),
            "reordered": mutation["reordered"],
            "dropped_fragments": mutation["dropped_fragments"],
            "tampered_windows": mutation["tampered_windows"],
            **decoded_info,
        }
        case_dir = RESULTS_DIR / name
        write_case_artifacts(case_dir, {**decoded_info, "decoded": decoded}, input_bits)
        (case_dir / "case_result.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        results.append(result)

    if results and results[0]["decode_success"]:
        DECODED_OUTPUT.write_bytes((RESULTS_DIR / results[0]["case"] / "decoded_output.bin").read_bytes())

    summary = {
        "scheme": "strategy5-path-sequence-offline-matrix",
        "random_seed": RANDOM_SEED,
        "bit_count": BIT_COUNT,
        "input_bits_file": str(INPUT_BITS),
        "input_payload_file": str(INPUT_PAYLOAD),
        "packets_generated": len(packets),
        "bits_per_window": 2,
        "packets_per_window": 3,
        "path_mapping": {
            "00": [0, 1, 2],
            "01": [0, 2, 1],
            "10": [1, 0, 2],
            "11": [1, 2, 0],
        },
        "results": results,
    }
    SUMMARY_JSON.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    with SUMMARY_CSV.open("w", newline="", encoding="utf-8-sig") as f:
        fieldnames = [
            "case",
            "received_packets",
            "packet_loss_count",
            "reordered",
            "decode_success",
            "complete",
            "exact_match",
            "bit_matches",
            "bit_total",
            "bit_match_ratio",
            "unknown_count",
            "reason",
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for item in results:
            decode_info = item.get("decode_info", {}) or {}
            writer.writerow({
                "case": item["case"],
                "received_packets": item["received_packets"],
                "packet_loss_count": item["packet_loss_count"],
                "reordered": item["reordered"],
                "decode_success": item["decode_success"],
                "complete": item["complete"],
                "exact_match": item["exact_match"],
                "bit_matches": item["bit_matches"],
                "bit_total": item["bit_total"],
                "bit_match_ratio": item["bit_match_ratio"],
                "unknown_count": len(decode_info.get("unknown_symbols", [])),
                "reason": decode_info.get("reason", ""),
            })

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
