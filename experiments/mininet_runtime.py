#!/usr/bin/env python3
"""
Mininet/BMv2 拓扑运行时工具。

该模块把 run.sh 里临时生成的拓扑代码沉淀为正式源码，供自动化
live 验证脚本复用。拓扑固定为：

    h1 -- s1 == 三条并行链路 == s2 -- h2

s1/s2 运行同一个 P4 JSON，端口约定如下：
    s1-eth1 <-> h1，s2-eth1 <-> h2
    s1/s2 的 eth2、eth3、eth4 分别对应 path0、path1、path2
"""

from __future__ import annotations

import argparse
import os
import shlex
import socket
import subprocess
import time
from pathlib import Path

try:
    from mininet.cli import CLI
    from mininet.link import TCLink
    from mininet.log import info, setLogLevel
    from mininet.net import Mininet
    from mininet.node import Switch
except ImportError:  # 允许在非 Mininet 环境中被单元测试安全导入。
    CLI = None
    TCLink = None
    Mininet = None
    Switch = None

    def info(message: str) -> None:
        print(message, end="")

    def setLogLevel(_level: str) -> None:
        return None


if Switch is not None:

    class P4Switch(Switch):
        """在 Mininet 中启动 simple_switch。"""

        def __init__(self, name, json_path, thrift_port, device_id, log_dir, **kwargs):
            super().__init__(name, **kwargs)
            self.json_path = json_path
            self.thrift_port = thrift_port
            self.device_id = device_id
            self.log_dir = log_dir
            self.simple_switch = os.environ.get("SIMPLE_SWITCH_BIN", "simple_switch")

        def start(self, controllers):
            intf_args = []
            for intf in self.intfList():
                if intf.name == "lo":
                    continue
                port = self.ports[intf]
                intf_args.extend(["-i", f"{port}@{intf.name}"])

            Path(self.log_dir).mkdir(parents=True, exist_ok=True)
            log_path = os.path.join(self.log_dir, f"{self.name}.log")
            pid_path = os.path.join(self.log_dir, f"{self.name}.pid")
            cmd = [
                self.simple_switch,
                "--device-id",
                str(self.device_id),
                "--thrift-port",
                str(self.thrift_port),
                *intf_args,
                self.json_path,
            ]
            shell_cmd = " ".join(shlex.quote(part) for part in cmd)
            self.cmd(
                f"{shell_cmd} > {shlex.quote(log_path)} 2>&1 "
                f"& echo $! > {shlex.quote(pid_path)}"
            )

        def stop(self, deleteIntfs=True):
            pid_path = os.path.join(self.log_dir, f"{self.name}.pid")
            self.cmd(
                f'if [ -f "{pid_path}" ]; then '
                f'kill "$(cat {pid_path})" >/dev/null 2>&1 || true; '
                f'rm -f "{pid_path}"; fi'
            )
            super().stop(deleteIntfs=deleteIntfs)

else:

    class P4Switch:  # pragma: no cover - 仅用于非 Mininet 环境占位。
        pass


def need_mininet() -> None:
    """确认当前环境已安装 Mininet。"""
    if Mininet is None or TCLink is None:
        raise RuntimeError("当前 Python 环境没有安装 Mininet，需在 P4 Ubuntu 虚拟机中运行。")


def cleanup_stale_mininet_state() -> None:
    """清理上次异常退出留下的 Mininet/BMv2 状态。"""
    subprocess.run(["mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    subprocess.run(["pkill", "-f", "simple_switch"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    for ipc_path in Path("/tmp").glob("bmv2-*-notifications.ipc"):
        try:
            ipc_path.unlink()
        except OSError:
            pass


def wait_for_thrift(port: int, timeout_s: float = 20.0) -> None:
    """等待 simple_switch thrift 端口就绪。"""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.2)
        try:
            sock.connect(("127.0.0.1", int(port)))
            sock.close()
            return
        except OSError:
            sock.close()
            time.sleep(0.2)
    raise RuntimeError(f"simple_switch thrift 端口未就绪：{port}")


def dump_switch_logs(log_dir: str) -> None:
    """启动失败时打印 BMv2 日志尾部，方便定位问题。"""
    for name in ("s1", "s2"):
        log_path = os.path.join(log_dir, f"{name}.log")
        info(f"\n*** {name} 日志尾部：{log_path}\n")
        if not os.path.exists(log_path):
            info("(日志文件不存在)\n")
            continue
        try:
            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()[-80:]
            if lines:
                for line in lines:
                    info(line)
            else:
                info("(日志为空)\n")
        except OSError as exc:
            info(f"(读取日志失败：{exc})\n")


def run_cli_file(thrift_port: int, name: str, cli_file: str, log_dir: str) -> None:
    """把 simple_switch_CLI 命令文件下发到指定交换机。"""
    cli_bin = os.environ.get("SIMPLE_SWITCH_CLI_BIN", "simple_switch_CLI")
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    out_file = os.path.join(log_dir, f"{name}_cli.log")
    info(f"*** 下发 {name} 流表：{cli_file}\n")
    with open(cli_file, "r", encoding="utf-8") as stdin, open(
        out_file, "w", encoding="utf-8"
    ) as stdout:
        subprocess.check_call(
            [cli_bin, "--thrift-port", str(thrift_port)],
            stdin=stdin,
            stdout=stdout,
            stderr=subprocess.STDOUT,
        )


def disable_offload(net) -> None:
    """关闭虚拟网卡卸载，避免 BMv2 转发 TCP/UDP 时出现校验和异常。"""
    features = "rx off tx off sg off tso off gso off gro off lro off"
    for node in net.hosts + net.switches:
        for intf in node.intfList():
            if intf.name == "lo":
                continue
            node.cmd(f"ethtool -K {intf.name} {features} >/dev/null 2>&1 || true")


def configure_mtu(net, host_mtu: int, trunk_mtu: int) -> None:
    """设置 MTU：终端侧保持常规 MTU，交换机间链路放大作为 INT 余量。"""
    host_ports = {"h1-eth0", "s1-eth1", "h2-eth0", "s2-eth1"}
    for node in net.hosts + net.switches:
        for intf in node.intfList():
            if intf.name == "lo":
                continue
            mtu = host_mtu if intf.name in host_ports else trunk_mtu
            node.cmd(f"ip link set dev {intf.name} mtu {mtu} >/dev/null 2>&1 || true")


def build_net(args):
    """创建 h1-s1-(三链路)-s2-h2 拓扑。"""
    need_mininet()
    if getattr(args, "cleanup", True):
        cleanup_stale_mininet_state()
    net = Mininet(controller=None, link=TCLink, autoSetMacs=False, autoStaticArp=True)

    h1 = net.addHost("h1", ip="10.0.1.1/24", mac="00:00:00:00:00:01")
    h2 = net.addHost("h2", ip="10.0.1.2/24", mac="00:00:00:00:00:02")

    s1 = net.addSwitch(
        "s1",
        cls=P4Switch,
        json_path=args.json,
        thrift_port=9090,
        device_id=1,
        log_dir=args.log_dir,
    )
    s2 = net.addSwitch(
        "s2",
        cls=P4Switch,
        json_path=args.json,
        thrift_port=9091,
        device_id=2,
        log_dir=args.log_dir,
    )

    net.addLink(h1, s1, port2=1)
    net.addLink(s1, s2, port1=2, port2=2, delay="5ms")
    net.addLink(s1, s2, port1=3, port2=3, delay="15ms")
    net.addLink(s1, s2, port1=4, port2=4, delay="30ms")
    net.addLink(s2, h2, port1=1)
    return net


def start_configured_net(args):
    """启动拓扑、设置 MTU/offload、下发两台交换机的基础流表。"""
    setLogLevel("info")
    net = build_net(args)
    net.start()
    configure_mtu(net, args.host_mtu, args.trunk_mtu)
    disable_offload(net)

    h1, h2 = net.get("h1", "h2")
    h1.setARP("10.0.1.2", "00:00:00:00:00:02")
    h2.setARP("10.0.1.1", "00:00:00:00:00:01")

    wait_for_thrift(9090)
    wait_for_thrift(9091)
    run_cli_file(9090, "s1", args.s1_cli, args.log_dir)
    run_cli_file(9091, "s2", args.s2_cli, args.log_dir)
    return net


def main() -> int:
    parser = argparse.ArgumentParser(description="启动 P4/Mininet 多路径拓扑")
    parser.add_argument("--json", required=True)
    parser.add_argument("--log-dir", required=True)
    parser.add_argument("--s1-cli", required=True)
    parser.add_argument("--s2-cli", required=True)
    parser.add_argument("--host-mtu", type=int, default=1500)
    parser.add_argument("--trunk-mtu", type=int, default=1600)
    parser.add_argument("--no-cleanup", action="store_true", help="跳过启动前 Mininet/BMv2 残留清理")
    args = parser.parse_args()
    args.cleanup = not args.no_cleanup

    net = None
    try:
        info("*** 启动 Mininet/BMv2\n")
        net = start_configured_net(args)
        info("\n*** 拓扑已启动\n")
        info("*** 主机：h1=10.0.1.1，h2=10.0.1.2\n")
        info("*** 交换机 thrift：s1=9090，s2=9091\n")
        info(f"*** MTU：终端侧={args.host_mtu}，s1-s2 链路={args.trunk_mtu}\n")
        info("*** 退出 Mininet CLI 后会自动清理 simple_switch\n\n")
        CLI(net)
        return 0
    except Exception:
        dump_switch_logs(args.log_dir)
        raise
    finally:
        if net is not None:
            info("*** 停止网络\n")
            net.stop()


if __name__ == "__main__":
    raise SystemExit(main())
