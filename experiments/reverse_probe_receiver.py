"""
反向主动 INT 探测接收端。

建议在地面端终端 h1 上运行。脚本既能记录普通 UDP 探测包，
也会尝试解析报文中的 INT shim/probe_data，并输出三条链路状态。
"""

import argparse
import json
from pathlib import Path
import socket
import sys
import time

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from python.control_plane.int_parser import IntParser, LinkMetricsCalculator
from python.control_plane.path_state_db import PathStateDB
from python.covert_strategies.ip_id_codec import IPIDCodec


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="地面端反向主动探测接收端")
    parser.add_argument("--iface", default=None, help="接收网卡，例如 h1-eth0")
    parser.add_argument("--dport", type=int, default=50100)
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--output", default="experiments/results/reverse_int_state.json")
    parser.add_argument("--window-ms", type=float, default=5000.0, help="链路状态滑动窗口长度，单位毫秒。")
    parser.add_argument("--write-interval", type=float, default=0.0, help="运行过程中周期写出结果文件，0表示只在结束时写一次。")
    parser.add_argument("--source-swid", type=int, default=2, help="INT源交换机ID，默认2用于h2->h1反向测量。")
    parser.add_argument("--sink-swid", type=int, default=1, help="INT终点交换机ID，默认1用于h2->h1反向测量。")
    parser.add_argument(
        "--mode",
        choices=["socket", "sniff"],
        default="socket",
        help="socket 直接收 UDP INT 报告；sniff 用 Scapy 抓包兼容旧格式。",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    from scapy.all import IP, UDP, Raw, sniff

    codec = IPIDCodec()
    int_parser = IntParser()
    calculator = LinkMetricsCalculator(
        port_to_link={2: 0, 3: 1, 4: 2},
        source_swid=args.source_swid,
        sink_swid=args.sink_swid,
    )
    db = PathStateDB(num_paths=3, window_size_ms=args.window_ms)

    received_probes = []
    int_reports = []
    parsed_reports = 0
    raw_metrics = {}
    metric_sample_counts = {0: 0, 1: 0, 2: 0}

    def build_result():
        states = {
            str(path_id): state.__dict__
            for path_id, state in db.get_all_states().items()
        }
        detail = {
            str(path_id): {
                "source_swid": metric.source_swid,
                "sink_swid": metric.sink_swid,
                "source_egress_port": metric.source_egress_port,
                "sink_ingress_port": metric.sink_ingress_port,
                "delay_us": metric.delay_us,
                "jitter_us": metric.jitter_us,
                "loss_rate": metric.loss_rate,
                "sample_loss_rate": metric.sample_loss_rate,
                "bw_bytes_per_s": metric.bw_bytes_per_s,
                "qdepth": metric.qdepth,
                "interval_us": metric.interval_us,
                "sent_delta": metric.sent_delta,
                "recv_delta": metric.recv_delta,
                "byte_delta": metric.byte_delta,
                "sequence_id": metric.sequence_id,
                "sequence_gap": metric.sequence_gap,
            }
            for path_id, metric in raw_metrics.items()
        }
        all_paths_ready = all(str(path_id) in states for path_id in range(3))
        return {
            "success": all_paths_ready,
            "all_paths_ready": all_paths_ready,
            "parsed_int_reports": parsed_reports,
            "metric_sample_counts": {
                str(path_id): count
                for path_id, count in metric_sample_counts.items()
            },
            "state_window_ms": args.window_ms,
            "source_swid": args.source_swid,
            "sink_swid": args.sink_swid,
            "received_probe_packets": len(received_probes),
            "probe_packets": received_probes[:20],
            "int_reports": int_reports,
            "raw_metrics": detail,
            "path_states": states,
        }

    def write_result():
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = output_path.with_suffix(output_path.suffix + ".tmp")
        tmp_path.write_text(json.dumps(build_result(), ensure_ascii=False, indent=2), encoding="utf-8")
        tmp_path.replace(output_path)

    def handle_int_payload(int_payload):
        nonlocal parsed_reports
        if not int_payload:
            return
        report = int_parser.parse(int_payload)
        if report is None:
            return
        parsed_reports += 1
        if len(int_reports) < 5:
            int_reports.append(
                {
                    "hop_count": report.hop_count,
                    "flags": report.flags,
                    "original_protocol": report.original_protocol,
                    "trace_id": report.trace_id,
                    "hops": [
                        {
                            "swid": hop.swid,
                            "port_ingress": hop.port_ingress,
                            "port_egress": hop.port_egress,
                            "byte_ingress": hop.byte_ingress,
                            "byte_egress": hop.byte_egress,
                            "count_ingress": hop.count_ingress,
                            "count_egress": hop.count_egress,
                            "curr_time_ingress": hop.curr_time_ingress,
                            "curr_time_egress": hop.curr_time_egress,
                            "qdepth": hop.qdepth,
                        }
                        for hop in report.hops
                    ],
                }
            )
        metrics = calculator.compute(report)
        for link_id, metric in metrics.items():
            metric_sample_counts[link_id] = metric_sample_counts.get(link_id, 0) + 1
            db.update(
                path_id=link_id,
                delay_us=metric.delay_us,
                jitter_us=metric.jitter_us,
                loss_rate=metric.loss_rate,
                bw_bytes_per_s=metric.bw_bytes_per_s,
                qdepth=metric.qdepth,
                sent_delta=metric.sent_delta,
                recv_delta=metric.recv_delta,
            )
            raw_metrics[link_id] = metric

    def handle_packet(packet):
        nonlocal parsed_reports
        if IP not in packet:
            return

        ip_id = int(packet[IP].id)
        ip_info = codec.unpack_ip_id(ip_id, nonce=len(received_probes))
        is_udp_int_report = UDP in packet and int(packet[UDP].dport) == args.dport
        if int(packet[IP].proto) != 0xFD and not is_udp_int_report and ip_info["covert_valid"]:
            received_probes.append(
                {
                    "ip_id": f"0x{ip_id:04x}",
                    "tag_valid": ip_info["tag_valid"],
                    "strategy_id": ip_info["strategy_id"],
                    "path_id": ip_info["path_id"],
                    "src": packet[IP].src,
                    "dst": packet[IP].dst,
                    "protocol": int(packet[IP].proto),
                }
            )

        int_payload = None
        if UDP in packet and int(packet[UDP].dport) == args.dport:
            int_payload = bytes(packet[UDP].payload)
        elif int(packet[IP].proto) == 0xFD:
            int_payload = bytes(packet[IP].payload)

        if int_payload is not None:
            handle_int_payload(int_payload)

    if args.mode == "socket":
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        sock.bind(("0.0.0.0", args.dport))
        sock.settimeout(0.2)
        deadline = time.time() + args.timeout
        next_write = time.time() + args.write_interval if args.write_interval > 0 else None
        while time.time() < deadline:
            try:
                payload, _addr = sock.recvfrom(4096)
            except socket.timeout:
                if next_write is not None and time.time() >= next_write:
                    write_result()
                    next_write = time.time() + args.write_interval
                continue
            handle_int_payload(payload)
            if next_write is not None and time.time() >= next_write:
                write_result()
                next_write = time.time() + args.write_interval
        sock.close()
    else:
        sniff(
            iface=args.iface,
            filter=f"udp port {args.dport} or ip proto 253",
            lfilter=lambda pkt: IP in pkt and (
                int(pkt[IP].proto) == 0xFD or
                (UDP in pkt and int(pkt[UDP].dport) == args.dport)
            ),
            prn=handle_packet,
            timeout=args.timeout,
            store=False,
        )

    result = build_result()

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
