"""
单策略隐蔽传输验证脚本。

用途：
1. 从输入文件读取待传输数据；
2. 调用指定隐蔽策略完成编码和解码；
3. 写出解码结果、验证摘要、包级轨迹 CSV；
4. 尽量生成可用 Wireshark 打开的 pcap 文件，便于中期审核抓包分析。
"""

import argparse
import csv
import json
from pathlib import Path
import struct
import sys
from typing import List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from python.covert_strategies.base import PacketSpec, StrategyID
from python.covert_strategies.strategy_registry import get_strategy


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="验证单个隐蔽传输策略的编解码流程")
    parser.add_argument(
        "--input",
        default="experiments/data/input_message.txt",
        help="待传输明文文件路径",
    )
    parser.add_argument(
        "--output",
        default="experiments/results/decoded_output.bin",
        help="解码后输出文件路径",
    )
    parser.add_argument(
        "--strategy",
        type=int,
        default=3,
        choices=[0, 1, 2, 3, 4, 5],
        help="要验证的策略编号",
    )
    parser.add_argument("--path-id", type=int, default=0, help="模拟使用的链路编号")
    parser.add_argument("--seq-num", type=int, default=1, help="模拟消息序号")
    parser.add_argument(
        "--summary",
        default="experiments/results/verify_summary.json",
        help="验证摘要输出路径",
    )
    parser.add_argument(
        "--trace",
        default="experiments/results/packet_trace.csv",
        help="包级轨迹 CSV 输出路径",
    )
    parser.add_argument(
        "--pcap",
        default="experiments/results/verify_packets.pcap",
        help="模拟抓包 pcap 输出路径；传空字符串可关闭",
    )
    return parser.parse_args()


def build_decode_inputs(packets: List[PacketSpec]) -> Tuple[List[bytes], List[dict]]:
    """
    将编码后的包描述转换为策略解码需要的载荷和元数据。
    """
    payloads: List[bytes] = []
    metadata: List[dict] = []
    current_time_ms = 0.0

    for index, pkt in enumerate(packets):
        if index == 0:
            current_time_ms = 0.0
        else:
            current_time_ms += float(pkt.send_delay_ms)

        packet_length = pkt.target_packet_length or len(pkt.payload) + 40
        payloads.append(pkt.payload)
        metadata.append(
            {
                "packet_index": index,
                "arrival_time_ms": current_time_ms,
                "ip_id": pkt.ip_id_field,
                "nonce": pkt.covert_nonce,
                "packet_length": packet_length,
                "target_packet_length": pkt.target_packet_length,
                "strategy_id": pkt.strategy_id,
                "path_id": pkt.path_id,
                "sequence_num": pkt.sequence_num,
                "fragment_id": pkt.fragment_id,
                "total_fragments": pkt.total_fragments,
            }
        )

    return payloads, metadata


def write_packet_trace(
    trace_path: Path,
    packets: List[PacketSpec],
    metadata: List[dict],
) -> None:
    """
    写出包级轨迹，方便不用 Wireshark 时直接检查每个策略的特征。
    """
    trace_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "packet_index",
        "strategy_id",
        "path_id",
        "sequence_num",
        "fragment_id",
        "total_fragments",
        "send_delay_ms",
        "arrival_time_ms",
        "ip_id_decimal",
        "ip_id_hex",
        "target_packet_length",
        "packet_length",
        "payload_bytes",
        "analysis_hint",
    ]

    with trace_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for pkt, meta in zip(packets, metadata):
            ip_id = pkt.ip_id_field
            writer.writerow(
                {
                    "packet_index": meta["packet_index"],
                    "strategy_id": pkt.strategy_id,
                    "path_id": pkt.path_id,
                    "sequence_num": pkt.sequence_num,
                    "fragment_id": pkt.fragment_id,
                    "total_fragments": pkt.total_fragments,
                    "send_delay_ms": pkt.send_delay_ms,
                    "arrival_time_ms": meta["arrival_time_ms"],
                    "ip_id_decimal": "" if ip_id is None else ip_id,
                    "ip_id_hex": "" if ip_id is None else f"0x{ip_id:04x}",
                    "target_packet_length": "" if pkt.target_packet_length is None else pkt.target_packet_length,
                    "packet_length": meta["packet_length"],
                    "payload_bytes": len(pkt.payload),
                    "analysis_hint": get_analysis_hint(pkt),
                }
            )


def get_analysis_hint(pkt: PacketSpec) -> str:
    """
    给包轨迹加一列人工可读提示，便于中期审核解释。
    """
    if pkt.strategy_id == 0:
        return "相对时序：观察连续两个 send_delay_ms 的大小关系"
    if pkt.strategy_id == 1:
        return "排序时序：每三个 send_delay_ms 组成一个排序窗口"
    if pkt.strategy_id == 2:
        return "IP-ID存储：观察 IPv4 Identification 的 covert_valid/tag/path/cipher"
    if pkt.strategy_id == 3:
        return "包长分布：观察 packet_length 落入哪个合法区间"
    if pkt.strategy_id == 4:
        return "LT冗余：观察 fragment_id 和 path_id 的跨路径分布"
    if pkt.strategy_id == 5:
        return "路径序列：IP-ID标识path/片段序号，每三个path_id排列承载2 bit"
    return "未知策略"


def write_pcap(
    pcap_path: Path,
    packets: List[PacketSpec],
    metadata: List[dict],
) -> Optional[str]:
    """
    生成模拟 pcap，文件中每个包都是 Ethernet/IP/UDP/Raw 格式。
    """
    if not str(pcap_path):
        return None

    pcap_path.parent.mkdir(parents=True, exist_ok=True)
    base_time = 1_700_000_000.0

    with pcap_path.open("wb") as f:
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for pkt, meta in zip(packets, metadata):
            frame = build_ethernet_frame(pkt, meta)
            timestamp = base_time + float(meta["arrival_time_ms"]) / 1000.0
            ts_sec = int(timestamp)
            ts_usec = int((timestamp - ts_sec) * 1_000_000)
            f.write(struct.pack("<IIII", ts_sec, ts_usec, len(frame), len(frame)))
            f.write(frame)
    return None


def build_ethernet_frame(pkt: PacketSpec, meta: dict) -> bytes:
    """
    构造一个可被 Wireshark 解析的 Ethernet/IP/UDP 数据帧。
    """
    target_ip_len = int(meta["packet_length"])
    ip_id = pkt.ip_id_field if pkt.ip_id_field is not None else (0x1000 + meta["packet_index"]) & 0xFFFF
    udp_payload_len = max(len(pkt.payload), target_ip_len - 20 - 8)
    udp_payload = pkt.payload
    if len(udp_payload) < udp_payload_len:
        udp_payload += bytes(
            (i * 31 + pkt.fragment_id) & 0xFF
            for i in range(udp_payload_len - len(udp_payload))
        )

    src_ip = bytes([10, 0, pkt.path_id + 1, 1])
    dst_ip = bytes([10, 0, pkt.path_id + 1, 2])
    udp_len = 8 + len(udp_payload)
    ip_total_len = 20 + udp_len

    ip_header_no_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        ip_total_len,
        ip_id,
        0,
        64,
        17,
        0,
        src_ip,
        dst_ip,
    )
    ip_header = ip_header_no_checksum[:10] + struct.pack("!H", ipv4_checksum(ip_header_no_checksum)) + ip_header_no_checksum[12:]
    udp_header = struct.pack("!HHHH", 40000 + pkt.path_id, 50000 + pkt.strategy_id, udp_len, 0)
    ether_header = bytes.fromhex("0200000000020200000000010800")
    return ether_header + ip_header + udp_header + udp_payload


def ipv4_checksum(header: bytes) -> int:
    """
    计算 IPv4 首部校验和。
    """
    total = 0
    for i in range(0, len(header), 2):
        total += (header[i] << 8) + header[i + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def main() -> int:
    args = parse_args()
    input_path = Path(args.input)
    output_path = Path(args.output)
    summary_path = Path(args.summary)
    trace_path = Path(args.trace)
    pcap_path = Path(args.pcap) if args.pcap else None

    if not input_path.exists():
        print(f"输入文件不存在: {input_path}")
        return 2

    data = input_path.read_bytes()
    strategy = get_strategy(StrategyID(args.strategy))

    packets = strategy.encode(data, path_id=args.path_id, seq_num=args.seq_num)
    payloads, metadata = build_decode_inputs(packets)
    decoded = strategy.decode(payloads, metadata)

    success = decoded == data
    output_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)

    if decoded is not None:
        output_path.write_bytes(decoded)

    write_packet_trace(trace_path, packets, metadata)
    pcap_error = write_pcap(pcap_path, packets, metadata) if pcap_path else None

    summary = {
        "success": success,
        "strategy_id": args.strategy,
        "strategy_name": strategy.name,
        "input_file": str(input_path),
        "output_file": str(output_path),
        "trace_file": str(trace_path),
        "pcap_file": str(pcap_path) if pcap_path else None,
        "pcap_error": pcap_error,
        "input_bytes": len(data),
        "decoded_bytes": len(decoded) if decoded is not None else 0,
        "packets_generated": len(packets),
        "first_packets": [
            {
                "fragment_id": pkt.fragment_id,
                "path_id": pkt.path_id,
                "send_delay_ms": pkt.send_delay_ms,
                "target_packet_length": pkt.target_packet_length,
                "ip_id_field": pkt.ip_id_field,
            }
            for pkt in packets[:8]
        ],
    }
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
