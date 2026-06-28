"""
反向主动 INT 探测发送端。

建议在低空侧终端 h2 上运行。脚本周期性发送 3 个 UDP 探测包，
每个包的 IPv4 Identification 字段都写入 path_id，便于终端侧区分探测包所属链路。
"""

import argparse
import time
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from python.covert_strategies.ip_id_codec import IPIDCodec


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="低空侧反向主动探测发送端")
    parser.add_argument("--dst-ip", required=True, help="地面端终端1的 IP 地址")
    parser.add_argument("--src-ip", default=None, help="低空侧终端2的源 IP，可选")
    parser.add_argument("--iface", default=None, help="发送网卡，例如 h2-eth0")
    parser.add_argument("--rounds", type=int, default=5, help="探测轮数")
    parser.add_argument("--interval", type=float, default=0.2, help="每轮间隔，单位秒")
    parser.add_argument("--sport", type=int, default=41000)
    parser.add_argument("--dport", type=int, default=50100)
    parser.add_argument("--dry-run", action="store_true", help="只打印计划，不实际发送")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    codec = IPIDCodec()

    total_packets = args.rounds * 3
    print(f"reverse_probe_packets={total_packets} rounds={args.rounds}")
    if args.dry_run:
        return 0

    from scapy.all import IP, UDP, Raw, send

    nonce = 0
    for round_id in range(args.rounds):
        for path_id in range(3):
            ip_id = codec.pack_ip_id(
                strategy_id=2,
                path_id=path_id,
                data_byte=round_id & 0xFF,
                nonce=nonce,
            )
            payload = f"REV_PROBE round={round_id} path={path_id}".encode("ascii")
            ip = IP(dst=args.dst_ip, id=ip_id)
            if args.src_ip:
                ip.src = args.src_ip
            packet = ip / UDP(sport=args.sport + path_id, dport=args.dport) / Raw(payload)
            send(packet, iface=args.iface, verbose=False)
            print(f"sent round={round_id} path={path_id} ip_id=0x{ip_id:04x}")
            nonce += 1
        time.sleep(args.interval)

    print("reverse_probe_send_done=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
