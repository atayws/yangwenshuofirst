# 面向低空网络的多路径隐蔽传输机制设计与实现

本项目用于毕业设计阶段验证：在低空网络的多路径环境中，利用 P4 交换机完成转发、路径调度和 INT 链路状态采集；隐蔽数据由终端侧 Python 策略库编码到正常业务流中，接收端再解码恢复。

当前重点是中期审核的阶段 1：先证明拓扑能通、INT 能测出三条链路状态，六个隐蔽策略都能挂载到真实 UDP 业务流上运行，并且接收端能够识别策略、解码隐蔽数据、继续转发原始业务流；PPO 强化学习暂不作为当前闭环的必要部分。

## 当前实现状态

| 模块 | 当前状态 | 说明 |
|---|---|---|
| P4 数据平面 | 已实现 | 两台交换机运行同一个 `p4/covert_int_switch.p4`，支持普通转发、固定路径、轮询路径、冗余复制、加权轮询和真实业务包 inline INT。 |
| INT 链路遥测 | 已实现并测试 | 默认验证 h2->h1 方向，s2 在采样命中的真实业务包中插入 INT，s1 解析后剥离 INT 并恢复业务包，同时本地生成 UDP/50100 报告给 h1，业务流不中断。 |
| 策略0 | 已实现并测试 | 高隐蔽相对时序，用两个连续间隔大小关系表示 0/1；已接入真实 `iperf -u` 业务流代理，发送前会根据 INT delay/jitter 自适应选择短/长间隔。 |
| 策略1 | 已实现并测试 | 高容量排序时序，用三个间隔排序表示 2 bit；已接入真实 `iperf -u` 业务流代理，排序间隔会根据 INT delay/jitter 自适应调整。 |
| 策略2/3/4/5 | 已实现并完成真实 UDP 业务流挂载验证 | 策略2 使用 IP-ID 块编码、三次重复、XOR 冗余和块认证；策略3 使用统计分布包长；策略4 使用 IP-ID 喷泉码和 P4 加权轮询；策略5 使用 IP-ID 自描述路径序列并重复挂载抗轻微丢包。 |
| 统一接收分发器 | 已搭建并离线验证 | `python/receiver/strategy_router.py` 可以从混合业务包中识别策略0-5，按策略缓冲并调用对应解码器；验证脚本会混入普通业务噪声包。 |
| 全局会话重组 | 已搭建并离线验证 | `python/covert_strategies/session.py` 把隐蔽数据切成带 `session_id/chunk_id/CRC` 的全局 chunk，接收端可跨策略按序重组。 |
| PPO 强化学习 | 阶段2 | 等 INT 和策略库稳定后，再把链路状态输入控制平面做自动策略选择。 |

## 拓扑

```text
h1 -- s1 == path0/path1/path2 == s2 -- h2

h1: 10.0.1.1，地面端/发送端
h2: 10.0.1.2，低空设备端/接收端
s1/s2: BMv2 simple_switch，运行同一个 P4 程序
path0: s1-eth2 <-> s2-eth2，默认 5ms
path1: s1-eth3 <-> s2-eth3，默认 15ms
path2: s1-eth4 <-> s2-eth4，默认 30ms
```

## 当前 INT 原理

当前版本采用真实业务包 inline INT，而不是额外发送一条独立探测流：

1. h1/h2 正常通信，例如 `iperf -u`。
2. INT source 交换机按采样间隔从真实业务流中选择一个业务包。
3. source 在该业务包的 IPv4 头后临时插入 `compact INT shim + probe_data`，shim 只记录原始 `protocol`、跳数和 `trace_id`；IPv4 长度在终点按 INT 实际长度扣回去。
4. 该业务包携带 INT 只穿过 s1-s2 之间的交换机间链路。
5. INT terminal 交换机补齐本端 probe_data，用本地组播复制两份：一份剥离 INT 并恢复成原业务包交给终端，另一份转换成 UDP/50100 INT 报告交给本地 Python 程序。
6. Python 接收程序根据连续报告计算每条路径的时延、丢包率、相对带宽负载和队列深度。

也就是说，INT 头不会交给 h1/h2 的普通应用；终端看到的业务流仍是正常 UDP/TCP/ICMP。报告包只在终点交换机本地送给解析程序，不再作为第二条遥测流穿过三条 s1-s2 链路。

`run.sh` 默认把终端侧 MTU 保持为 1500，把三条交换机间链路 MTU 设置为 1600，同时关闭 Mininet 虚拟网卡 offload，避免 BMv2 转发 TCP/UDP 时出现校验和问题。

## 路径调度

P4 通过寄存器控制路径模式，可以用 `simple_switch_CLI` 切换：

| 模式 | `reg_path_mode` | 说明 |
|---|---:|---|
| 默认路由 | 0 | 按 `ipv4_lpm` 表转发。 |
| 固定链路 | 1 | 所有跨交换机业务包走 `reg_fixed_path` 指定 path0/1/2。 |
| 轮询链路 | 2 | 每 `reg_rr_burst_size` 个包切换到下一条 path。 |
| 冗余链路 | 3 | 通过 BMv2 multicast group 把同一个业务包复制到三条链路。 |
| 加权轮询 | 4 | 按 `reg_wrr_weight0/1/2` 对三条 path 做加权轮询，当前用于策略4多路径协同。 |

阶段 1 建议用固定链路和轮询链路验证；阶段 2 再由 PPO 控制这些寄存器或表项。

## 隐蔽策略库

| ID | 策略 | 当前设计 | 阶段1验证情况 |
|---:|---|---|---|
| 0 | 高隐蔽相对时序 | 两个连续间隔的大小关系表示 0/1，短-长为 0，长-短为 1。 | 已通过真实 UDP 业务流代理闭环。 |
| 1 | 高容量排序时序 | 一个窗口内三个间隔的排序表示 2 bit。 | 已通过真实 UDP 业务流代理闭环。 |
| 2 | 高可靠协议存储型 | IPv4 Identification 字段携带 `flag + strategy_id + seq_mod + encrypted_value`，每块 12 数据 + 3 XOR 冗余 + 1 块认证。 | 已通过真实 UDP 业务流代理闭环。 |
| 3 | 统计特征融合 | 通过合法包长区间承载 2 bit 符号，payload 前有加密同步小头用于分组和顺序恢复。 | 已通过真实 UDP 业务流代理闭环，要求业务 UDP payload 不接近 MTU。 |
| 4 | IP-ID 喷泉码多路径协同 | IPv4 Identification 字段携带 `flag + strategy_id + frame_id + symbol_id + encrypted coded_nibble`，P4 用加权轮询分发到两条或三条链路。 | 已通过真实 UDP 业务流代理闭环，策略4不能单路径单独使用。 |
| 5 | 多路径路径序列 | IP-ID 自描述策略/路径/片段号，真实隐蔽数据由三包路径排列表示 2 bit。 | 已通过真实 UDP 业务流代理闭环，代理层重复挂载提升轻微丢包下的可解码概率。 |

策略0/1目前使用“方案B”：在代理间 UDP 负载前增加 2 字节同步标签。标签只用于识别“这个业务包参与隐蔽时序窗口”以及恢复窗口索引，真正的隐蔽比特仍由包间隔承载。接收端遇到少量标签包丢失时不会整体错位，而是把局部 bit 或 symbol 标记为 unknown。

策略0/1的时间间隔已经改成 INT 驱动的自适应配置：干净链路会缩短间隔提高发送速度，高抖动链路会自动拉大保护间隔；普通演示模式下如果链路抖动或丢包明显，规则选择器会优先切到策略2/3，避免时序策略拖慢长消息。当前 VM 验证中，低抖动链路下策略0使用 `8ms/22ms`，策略1使用 `12ms/24ms/42ms`；当链路抖动升高到约 29ms 以上时，策略0自动放大到 `100ms/220ms`，策略1放大到 `100ms/180ms/300ms`。

## 关键目录

```text
p4/
  covert_int_switch.p4        单文件 P4 程序
  s1_commands.txt             s1 默认流表和寄存器配置
  s2_commands.txt             s2 默认流表和寄存器配置
python/covert_strategies/     隐蔽策略库
  session.py                  全局隐蔽会话切块和重组
python/receiver/              统一策略接收分发器
python/control_plane/         INT 报告解析与链路状态计算
experiments/udp_covert_proxy.py
                              真实 UDP 业务流上的策略0-5统一代理
experiments/verify_udp_proxy_real_flow.py
                              六策略真实 UDP 业务流挂载验证脚本
experiments/run_rule_proxy_closed_loop.py
                              一键真实业务流闭环复测：INT、规则选策略、六策略挂载和业务转发
experiments/run_dynamic_rule_proxy_closed_loop.py
                              长消息传输中途改变链路状态的动态切换闭环复测
experiments/run_interactive_closed_loop.py
                              历史兼容交互闭环演示：自动启动拓扑、业务流、INT、规则选策略和收发重组
experiments/user_demo/        五窗口用户演示程序：拓扑服务、发送、接收显示、链路状态、链路设置
int-test/                     INT 多路径遥测验证文档和结果
proxy-test/                   早期策略0/1真实 UDP 业务流代理验证文档和结果
celue0/ celue1/               策略0/1单独测试数据与报告
celue2/                       策略2 IP-ID 抗丢包测试脚本、数据与报告
celue3/                       策略3统计分布包长信道说明与离线样例
docs/                         技术文档和中期验证说明
run.sh                        一键编译 P4、启动 Mininet/BMv2、下发流表
```

## 快速验证入口

进入虚拟机项目目录：

```bash
cd /home/p4/yws-covert
```

启动基础拓扑：

```bash
sudo bash run.sh
```

`run.sh` 和五窗口拓扑服务都会在启动前清理旧 Mininet/BMv2 状态，避免上次异常退出后残留的 `h1-eth0/s1-eth1` 等 veth 接口导致 `RTNETLINK answers: File exists`。如果只是演示五窗口，优先直接运行下面的 `topology_service.py`，它还会先处理旧服务占用 `127.0.0.1:38765` 的情况，再启动 Mininet。

进入 Mininet CLI 后先检查连通性：

```bash
h1 ping -c 5 10.0.1.2
h2 ping -c 5 10.0.1.1
```

五窗口用户演示入口：

```bash
# 窗口1：一键启动拓扑服务，保持运行
sudo python3 experiments/user_demo/topology_service.py --clean-results

# 窗口2：接收端实时显示 h2 解码结果
python3 experiments/user_demo/receiver_window.py

# 窗口3：动态显示 INT 链路状态和建议策略
python3 experiments/user_demo/link_status_window.py

# 窗口4：发送端输入隐蔽数据
python3 experiments/user_demo/sender_window.py

# 窗口5：按需设置链路时延/丢包
python3 experiments/user_demo/link_config_tool.py
```

链路设置支持这种输入：

```bash
python3 experiments/user_demo/link_config_tool.py 1 20 10 2 10 20 3 30 30
```

含义是：链路1 delay=20ms/loss=10%，链路2 delay=10ms/loss=20%，链路3 delay=30ms/loss=30%。完整说明见 `experiments/user_demo/操作说明.md`。

中期一键交互式闭环演示：

```bash
sudo python3 experiments/run_interactive_closed_loop.py --clean-results
```

脚本会自动启动 `h1-s1-(三条链路)-s2-h2` 拓扑，在后台运行 h2->h1 UDP `iperf` 触发 INT，h1 周期性解析三条链路状态。启动后直接输入要隐蔽传输的文本，回车发送；输入 `/quit` 退出。

非交互复测可以用：

```bash
sudo python3 experiments/run_interactive_closed_loop.py \
  --clean-results \
  --demo-once "MIDTERM CLOSED LOOP TEST 1234567890" \
  --timeout 60
```

结果目录：

```text
experiments/results/interactive_closed_loop/
experiments/results/interactive_closed_loop/summary.json
experiments/results/interactive_closed_loop/history.csv
experiments/results/interactive_closed_loop/session_XXX/
```

INT 验证看这里：

```text
int-test/操作文档.md
int-test/INT测试报告.md
int-test/results/summary.csv
```

六策略真实 UDP 业务流挂载验证：

```bash
sudo python3 experiments/verify_udp_proxy_real_flow.py \
  --strategies 0,1,2,3,4,5 \
  --iperf-time 5 \
  --case-timeout 35 \
  --iperf-rate 180K \
  --iperf-len 200 \
  --clean-results
```

结果文件：

```text
experiments/results/udp_proxy_real_flow/summary.json
```

阶段1相关单元测试：

```bash
python3 -m unittest tests.test_strategies -v
```

统一接收分发器离线验证：

```bash
python3 experiments/verify_strategy_router.py
```

手动策略计划的全局会话闭环验证：

```bash
python3 experiments/verify_manual_policy_session.py
```

输出文件：

```text
experiments/results/router_summary.json
experiments/results/router_trace.csv
experiments/results/router_decoded/
experiments/results/manual_policy/summary.json
experiments/results/manual_policy/chunk_assignments.csv
experiments/results/manual_policy/decoded_secret.bin
```

当前 VM 上最新结果：六策略真实 UDP 业务流挂载验证已通过，`experiments/results/udp_proxy_real_flow/summary.json` 中 `success=true`；策略0/1/2/3/4/5 均完成隐蔽数据解码，接收端同时把业务包继续转发给 h2 的 `iperf -u` server。交互式闭环脚本已在 VM 中用 `--demo-once "MIDTERM CLOSED LOOP TEST 1234567890"` 验证通过，`summary.json` 中 `success=true`、`iperf_ok=true`、`int_success=true`，h1 解析到三条路径的 INT 状态，h2 恢复文本与输入一致。

当前推荐的一体化复测入口是：

```bash
sudo python3 experiments/run_rule_proxy_closed_loop.py \
  --clean-results \
  --timeout 85 \
  --iperf-rate 220K \
  --iperf-len 200
```

该脚本已经在 VM 通过：两个链路场景均 `success=true`、`hidden_match=true`、`int_success=true`，六个策略都挂载在真实 UDP `iperf` 业务流包上，h2 侧继续收到业务 payload。默认场景使用 `S0/S1/S3/S4/S5/S2`，链路变化场景会根据 INT 状态改变策略与路径计划。

长消息传输中途动态切换复测入口是：

```bash
sudo python3 experiments/run_dynamic_rule_proxy_closed_loop.py \
  --clean-results \
  --timeout 140 \
  --iperf-rate 260K \
  --iperf-len 200
```

该脚本验证升级后的 chunk 级在线重规划能力：长隐蔽消息按 segment 顺序发送，每个 segment 开始前重新读取最新 INT 状态并重写该 segment 的策略/路径；传输中主动改变链路 delay/loss 后，后续 segment 会自动切到新的策略和路径继续传输。VM 验证结果位于 `experiments/results/dynamic_rule_proxy_closed_loop/summary.json`，关键字段为 `success=true`、`hidden_match=true`、`all_six_strategies_seen=true`、`strategy_changed_after_network_change=true`、`path_changed_after_network_change=true`、`int_success=true`、`iperf_server_received=true`。需要注意，当前动态切换是 chunk 边界切换，不是包级任意切换；这样可以保护策略0/1时序窗口、策略4喷泉码窗口和策略5路径序列窗口不被中途打断。

五窗口演示也已切换到同一套真实业务流代理。VM 服务级验证结果：

```text
默认链路:
  输入 MIDTERM_PROXY_FLOW_六策略真实业务流闭环测试_0123456789
  hidden_match=true，策略计划 S0@[0] | S1@[1] | S3@[2] | S4@[0,1,2] | S5@[0,1,2] | S2@[0]

修改链路 1 60 8 2 10 0 3 25 2:
  输入 AFTER_LINK_CHANGE_自动规则切换验证_abcdef0123456789
  hidden_match=true，策略计划 S0@[0] | S1@[1] | S3@[1] | S2@[0] | S4@[1,2,0] | S5@[0,1,2]
```

当前五窗口发送入口也已升级为 chunk 级动态重规划：窗口4提交长文本后，服务先为每个 segment 预留端口和顺序；每个 segment 真正发送前，窗口1服务重新读取 `latest_int_summary.json`，用规则选择器选择当前 segment 的策略/路径，改写 `proxy_plan.json`，再放行真实 UDP `iperf` 业务包。窗口3会显示当前正在运行的 segment、策略和路径，窗口5运行中修改链路状态后，后续 segment 会按新的 INT 状态继续选择策略。

为解决长输入过慢和长输入失败的问题，五窗口默认发送路径已经做了两点调整：第一，默认分段从 6 字节提高到 64 字节，避免长文本被切成过多 segment；第二，策略选择同时参考 INT 测量值和窗口5手动设置的 netem delay/loss，刚设置为丢包的链路会立即被避开，除非所有链路都不健康才使用策略2可靠模式。最新 VM 回归结果：64 字节、256 字节、1024 字节文本均 `success=true`、误码率 `0%`；其中 1024 字节从旧版约 87.8s 降到约 28.0s。将 path0 设置为 2% 丢包后发送 256 字节，系统自动只使用 path1/path2，仍 `success=true`、误码率 `0%`。

## 文档入口

- `docs/implementation_guide.md`：当前实现原理，包括 P4、INT、路径调度、六策略真实 UDP 业务流挂载、五窗口动态重规划。
- `docs/midterm_validation.md`：中期审核建议验证流程和最新复测结果。
- `docs/中期审核答辩材料.md`：PPT 可直接提炼的背景、方案、创新点、难点和实验结果。
- `int-test/操作文档.md`：INT 功能如何手动验证。
- `proxy-test/操作文档.md`：早期策略0/1真实 UDP 业务流验证记录。

### 阶段1一体化闭环说明

当前已经验证的完整闭环是：六个策略都可以通过 `experiments/udp_covert_proxy.py` 挂载到真实 UDP 业务流。h1 侧代理接收本机 `iperf -u` 业务包，把策略字段叠加到这些业务包上；h2 侧代理抓取业务包、识别当前策略、解码隐蔽数据，再剥离代理层字段并把原始业务 payload 转发给 h2 的 `iperf` server。h2 到 h1 的反向业务流由 s2 轮询三条路径并触发 INT，h1 接收 UDP/50100 报告后得到 path0/path1/path2 的链路状态。不要把同一个策略0/1时序窗口直接轮询到三条不同延迟路径，否则多路径时延差会破坏包间隔关系。

最新一体化结果见：`proxy-test/full_stage1_results_fixed/summary.json`。

## 统一接收分发器

接收端现在新增了统一策略分发框架，入口文件是：

```text
python/receiver/strategy_router.py
```

它的作用是把接收端抓到的业务包转换成统一格式：

```text
payload + metadata(ip_id、packet_length、arrival_time_ms、path_id、端口等)
```

然后按以下优先级识别策略并分组：

1. 策略2/4/5：读取 IPv4 Identification 中的 `flag + strategy_id` 等自描述字段。
2. 策略3：解析 payload 前部的加密同步小头。
3. 策略0/1：解析两字节时序同步标签，并保留 `arrival_time_ms` 用于时序解码。
4. 普通业务包：无法匹配上述格式的包会被忽略，不进入隐蔽解码缓冲区。

验证脚本 `experiments/verify_strategy_router.py` 会生成六种策略的承载包，混入普通业务噪声包并打乱顺序，再由分发器自动识别、分组和解码。当前 VM 结果中 6 个策略全部成功恢复，24 个普通业务噪声包被忽略。这个脚本验证的是“接收端闭环框架”。真实 live 混合部署目前由 `experiments/run_manual_policy_live.py` 和 `experiments/run_interactive_closed_loop.py` 负责：发送端按计划切换路径和策略，接收端抓包、识别策略、解码 chunk，并由全局会话层按 `chunk_id` 重组。

## 手动策略计划闭环

中期阶段先不用 PPO，先使用手动策略计划验证“多链路不同策略 + 接收端统一重组”的核心流程。新增验证脚本：

```bash
python3 experiments/verify_manual_policy_session.py
```

当前默认计划为：

```text
path0 -> 策略0：相对时序
path1 -> 策略2：可靠 IP-ID
path0+path1 -> 策略4：IP-ID 喷泉码多路径协同
path2 -> 策略3：包长统计
```

注意：策略4不是单路径策略，必须绑定至少两条路径，例如 `path0+path1` 或 `path0+path1+path2`。脚本中已经做了校验，如果把策略4配置成单路径会直接报错。

发送端先由 `CovertSessionFramer` 把隐蔽数据切成全局 chunk，每个 chunk 带 `session_id/chunk_id/total_chunks/payload_len/CRC`。不同 chunk 可以交给不同策略和路径发送。接收端由 `StrategyReceiverRouter` 自动识别策略并解码出 chunk，再由 `CovertSessionAssembler` 按 `chunk_id` 重组最终隐蔽数据。

当前 VM 离线结果：95 字节隐蔽数据被切成 12 个 chunk，分别走策略0/2/4/3，策略4使用 path0+path1，两端最终 `hidden_match=true`。

真实 Mininet/BMv2 的手动策略计划入口是：

```bash
sudo python3 experiments/run_manual_policy_live.py --timeout 60 --clean-results
```

该 live 脚本会同时启动 h2->h1 UDP `iperf` 触发 INT，并让 h1->h2 发送带全局 chunk 的隐蔽数据。为了保证中期演示稳定，live 主计划使用策略2、策略3、策略4：`path0 -> 策略2`，`path2 -> 策略3`，`path0+path1 -> 策略4`。策略4仍然强制至少两条路径。六策略“直接挂载真实 UDP 业务流”的验证由 `experiments/verify_udp_proxy_real_flow.py` 负责。

真实 VM live 验证已经跑通，S2/S3/S4 统一分发和全局重组可以恢复 `LIVE_MANUAL_POLICY_STAGE1_OK`。结果目录为：

```text
experiments/results/manual_policy_live/
```

## 阶段二规则控制闭环

PPO 正式训练前，项目已经加入一个可运行的规则控制基线：

```bash
sudo python3 experiments/run_stage2_rule_live.py --timeout 60 --clean-results
```

该脚本会先运行一轮 live 业务流获取 INT 三路径状态，再由 `python/control_plane/rule_policy_selector.py` 生成策略计划文件，最后按自动计划运行第二轮 live。当前 VM 结果为 `success=true`、`rule_hidden_match=true`、`rule_iperf_ok=true`、`rule_int_success=true`。本次规则计划根据三条链路低丢包、低抖动状态选择策略3作为主要承载，并保留策略4的三路径喷泉码协同项，结果保存在：

```text
experiments/results/stage2_rule_live/
```

后续接入 PPO 时，只需要让 PPO 输出同样格式的 `rule_plan.json`，现有发送端、接收端和 P4 路径控制可以继续复用。

## 交互式中期闭环

如果需要在演示时实时输入隐蔽数据，优先使用 `experiments/user_demo/` 五窗口演示。该入口已经使用真实 UDP `iperf` 业务流代理，窗口4输入文本后，隐蔽数据会挂载到 h1 本机 `iperf -u` 产生的业务包上，经 P4 多路径转发到 h2，再由 `plan-receiver` 解码并转发原始业务 payload 给 h2 的 `iperf` server。

自动复测推荐使用：

```bash
sudo python3 experiments/run_rule_proxy_closed_loop.py --clean-results --timeout 85
```

旧的单窗口交互脚本仍保留为兼容入口：

```bash
sudo python3 experiments/run_interactive_closed_loop.py --clean-results
```

运行后脚本完成以下闭环：

1. 自动启动 P4/Mininet 三路径拓扑。
2. h2->h1 后台 UDP `iperf` 持续运行，s2 按采样间隔在真实业务包上 inline 插入 INT，s1 剥离 INT 后本地生成 UDP/50100 报告，h1 实时解析三条链路状态。
3. h1 终端输入任意长度文本；短文本走当前最优单路径，长文本按全局 chunk 切分。
4. 规则选择器根据最新 INT 状态生成策略计划；当前稳定 live 主体使用策略2、策略3和策略4，策略4必须绑定至少两条路径。
5. h1 按计划发送隐蔽承载包，h2 统一接收分发、按策略解码，再按 `chunk_id` 重组并打印恢复出的文本。

需要注意：旧单窗口脚本中的隐蔽承载流程仍偏向历史手动 chunk 发送；当前中期演示和闭环复测以五窗口服务和 `run_rule_proxy_closed_loop.py` 为准。

## 策略2优化说明

策略2已经升级为可靠 IP-ID 存储信道。它不再按接收顺序直接拼接字节，而是把隐蔽数据切成 16 个承载包一组的块：`seq_mod=0~11` 为 12 字节数据，`seq_mod=12~14` 为 3 个 XOR 冗余字节，`seq_mod=15` 为 1 字节块认证。接收端先根据 IP-ID 中的 `strategy_id` 和 `seq_mod` 做候选分流，再按块内序号重排，最后通过块认证确认该块有效。

这样可以解决两个问题：普通业务包即使偶然长得像隐蔽包，也很难通过整块认证；多路径导致包乱序时，接收端也能按 `seq_mod` 放回正确位置。当前单元测试已经覆盖策略2乱序、每个 XOR 组丢 1 个数据片段恢复、错误 IP-ID 被认证拒绝。


## 策略2 live 矩阵验证

策略2已完成链路0上的 live 矩阵测试：64 字节输入生成 576 个承载包，在 5ms/20ms/50ms 无丢包以及 5%、10%、20%、30% 随机丢包设置下均 `hidden_match=true`。

复现命令：

```bash
sudo python3 celue2/run_strategy2_matrix.py --timeout 25
```

详细说明见 `celue2/操作文档.md`、`celue2/测试报告.md` 和 `celue2/results/summary.csv`。


## 策略3优化说明

策略3已从简单包长区间映射升级为统计分布包长信道：发送端先对白化后的隐蔽数据按 2 bit 切分，再通过伪随机符号映射选择合法包长区间；每个符号默认重复 3 次，接收端根据加密同步小头按 `symbol_index` 重排并投票恢复。

离线验证：

```bash
python3 -m unittest tests.test_strategies.TestStatisticalFusion -v
```

说明文件见 `celue3/操作说明.md`。

## 策略4 live 矩阵验证

策略4已经升级为 IP-ID 喷泉码多路径协同隐蔽传输：IP-ID 使用 `flag + strategy_id + frame_id + symbol_id + encrypted coded_nibble`，接收端按 frame 收集 symbol 并用 GF(2) 消元恢复。P4 侧不解析隐蔽内容，只通过 `reg_path_mode=4` 和 `reg_wrr_weight0/1/2` 做加权轮询。

当前 live 测试参数为 `k=4, num_output=16`，23 字节输入生成 256 个承载包。矩阵测试覆盖三路径等权、path2 20% 丢包、path2 降权、两路径、两路径 path1 30% 丢包、三路径均 10% 丢包，6/6 场景均 `hidden_match=true`，同时 h2->h1 UDP iperf 和 INT 均正常。

复现命令：

```bash
sudo python3 celue4/run_strategy4_matrix.py --timeout 15
```

详细说明见 `celue4/操作文档.md`、`celue4/测试报告.md` 和 `celue4/results/summary.csv`。
## 策略5路径序列信道说明

策略5利用多路径系统本身承载隐蔽信息：一个符号窗口包含 3 个承载包，窗口内 `path_id` 排列表示 2 bit。例如 `path0->path1->path2` 表示 `00`，`path0->path2->path1` 表示 `01`。该策略使用 IP-ID 做轻量自描述，但不直接在 IP-ID 中写真实隐蔽比特，隐蔽性仍强，适合体现本课题的“三链路多路径协同”特色。

当前已实现编码、解码、乱序重排和离线矩阵验证。IP-ID 布局为 `valid + strategy_id=5 + path_id + encrypted fragment_id_mod1024`，用于识别策略、路径和顺序；真实隐蔽比特仍由路径排列承载。100 bit 测试中，顺序和全局乱序均完整恢复；数据区丢 1 个包时 99/100 bit 匹配，稀疏丢 3 个包时 97/100 bit 匹配，后续窗口不会整体错位。策略5 live 化需要让 P4/控制面按 `PacketSpec.path_id` 控制每个窗口内承载包实际走对应路径。详细说明见 `celue5/操作说明.md`、`celue5/测试报告.md` 和 `celue5/results/summary.csv`。
