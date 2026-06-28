"""
一键验证六个隐蔽传输策略。

该脚本依次调用 experiments/verify_transmission.py，
为每个策略生成解码文件、摘要、包轨迹 CSV 和模拟抓包 pcap。
"""

import argparse
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="一键验证六个隐蔽传输策略")
    parser.add_argument(
        "--input",
        default="experiments/data/input_message.txt",
        help="待传输输入文件",
    )
    parser.add_argument(
        "--output-dir",
        default="experiments/results",
        help="验证结果输出目录",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    failed = []
    for strategy_id in range(6):
        cmd = [
            sys.executable,
            "experiments/verify_transmission.py",
            "--strategy",
            str(strategy_id),
            "--input",
            args.input,
            "--output",
            str(output_dir / f"decoded_s{strategy_id}.bin"),
            "--summary",
            str(output_dir / f"verify_s{strategy_id}.json"),
            "--trace",
            str(output_dir / f"trace_s{strategy_id}.csv"),
            "--pcap",
            str(output_dir / f"packets_s{strategy_id}.pcap"),
        ]
        print(f"\n=== 验证策略 {strategy_id} ===")
        result = subprocess.run(cmd, cwd=PROJECT_ROOT)
        if result.returncode != 0:
            failed.append(strategy_id)

    if failed:
        print(f"\n验证失败的策略: {failed}")
        return 1

    print("\n六个策略均验证通过。结果目录:")
    print(output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
