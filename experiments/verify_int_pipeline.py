"""
INT 解析与链路状态计算验证脚本。

该脚本构造模拟的两跳 INT 报告：
s1 为发送端交换机，s2 为低空设备侧交换机。
每条链路生成两次快照，用差值法计算带宽、丢包、时延、抖动和队列深度。
"""

import argparse
import json
from pathlib import Path
import struct
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from python.control_plane.int_parser import IntParser, LinkMetricsCalculator
from python.control_plane.path_state_db import PathStateDB


PROBE_DATA_SIZE = 48
INT_SHIM_SIZE = 12


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="验证 INT 报告解析和链路状态计算")
    parser.add_argument(
        "--output",
        default="experiments/results/int_state.json",
        help="链路状态输出 JSON 路径",
    )
    parser.add_argument(
        "--direction",
        choices=["forward", "reverse"],
        default="forward",
        help="forward 表示 s1->s2，reverse 表示 s2->s1 反向主动探测",
    )
    return parser.parse_args()


def pack_u48(value: int) -> bytes:
    return int(value).to_bytes(6, byteorder="big", signed=False)


def pack_hop(
    swid: int,
    port_ingress: int,
    port_egress: int,
    byte_ingress: int,
    byte_egress: int,
    count_ingress: int,
    count_egress: int,
    last_time_ingress: int,
    last_time_egress: int,
    curr_time_ingress: int,
    curr_time_egress: int,
    qdepth: int,
) -> bytes:
    data = struct.pack("!BBBB", swid, port_ingress, port_egress, 0)
    data += struct.pack("!IIII", byte_ingress, byte_egress, count_ingress, count_egress)
    data += pack_u48(last_time_ingress)
    data += pack_u48(last_time_egress)
    data += pack_u48(curr_time_ingress)
    data += pack_u48(curr_time_egress)
    data += struct.pack("!I", qdepth)
    assert len(data) == PROBE_DATA_SIZE
    return data


def build_report(link_id: int, sample_index: int, direction: str = "forward") -> bytes:
    """
    构造一条包含 s1/s2 两跳快照的 INT 报告。
    """
    link_port = 2 + link_id
    base_time = 1_000_000 + sample_index * 100_000
    delay_us = [5000, 15000, 30000][link_id]
    sent_packets = [100, 90, 80][link_id] * (sample_index + 1)
    recv_packets = sent_packets - [0, 2, 5][link_id] * sample_index
    sent_bytes = [120_000, 100_000, 80_000][link_id] * (sample_index + 1)
    recv_bytes = int(sent_bytes * (recv_packets / max(sent_packets, 1)))

    if direction == "forward":
        source_swid, sink_swid = 1, 2
    else:
        source_swid, sink_swid = 2, 1

    source = pack_hop(
        swid=source_swid,
        port_ingress=1,
        port_egress=link_port,
        byte_ingress=sent_bytes,
        byte_egress=sent_bytes,
        count_ingress=sent_packets,
        count_egress=sent_packets,
        last_time_ingress=base_time - 100_000,
        last_time_egress=base_time - 100_000,
        curr_time_ingress=base_time - 200,
        curr_time_egress=base_time,
        qdepth=0,
    )
    sink = pack_hop(
        swid=sink_swid,
        port_ingress=link_port,
        port_egress=1,
        byte_ingress=recv_bytes,
        byte_egress=recv_bytes,
        count_ingress=recv_packets,
        count_egress=recv_packets,
        last_time_ingress=base_time - 100_000 + delay_us,
        last_time_egress=base_time - 100_000 + delay_us + 200,
        curr_time_ingress=base_time + delay_us,
        curr_time_egress=base_time + delay_us + 200,
        qdepth=[2, 8, 16][link_id],
    )

    shim = struct.pack("!BBBBBBHHH", 1, 2, 48, 2, 0xFF, 17, 64, 1, link_id + 1)
    assert len(shim) == INT_SHIM_SIZE
    return shim + source + sink


def main() -> int:
    args = parse_args()
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    parser = IntParser()
    if args.direction == "forward":
        source_swid, sink_swid = 1, 2
    else:
        source_swid, sink_swid = 2, 1
    calculator = LinkMetricsCalculator(
        port_to_link={2: 0, 3: 1, 4: 2},
        source_swid=source_swid,
        sink_swid=sink_swid,
    )
    db = PathStateDB(num_paths=3)

    raw_metrics = {}
    for sample_index in range(2):
        for link_id in range(3):
            report = parser.parse(build_report(link_id, sample_index, args.direction))
            metrics = calculator.compute(report)
            for mid, metric in metrics.items():
                db.update(
                    path_id=mid,
                    delay_us=metric.delay_us,
                    jitter_us=metric.jitter_us,
                    loss_rate=metric.loss_rate,
                    bw_bytes_per_s=metric.bw_bytes_per_s,
                    qdepth=metric.qdepth,
                )
                raw_metrics[mid] = metric

    states = {
        str(path_id): state.__dict__
        for path_id, state in db.get_all_states().items()
    }
    detail = {
        str(path_id): {
            "delay_us": metric.delay_us,
            "jitter_us": metric.jitter_us,
            "loss_rate": metric.loss_rate,
            "bw_bytes_per_s": metric.bw_bytes_per_s,
            "qdepth": metric.qdepth,
        }
        for path_id, metric in raw_metrics.items()
    }
    result = {
        "success": len(states) == 3,
        "direction": args.direction,
        "source_swid": source_swid,
        "sink_swid": sink_swid,
        "raw_metrics": detail,
        "path_states": states,
    }

    output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
