# 实现原理文档

**文档版本**：v4.4  
**更新日期**：2026-06-28  
**当前阶段**：中期审核阶段，优先保证阶段1闭环可演示。

## 1. 阶段划分

### 阶段1：中期审核目标

阶段1只要求证明基础系统可运行：

1. h1 与 h2 可以正常通信，`ping` 和 `iperf` 不因为 INT 或多路径转发中断。
2. INT 可以在三条 s1-s2 链路上采集状态，输出时延、丢包率、相对带宽负载和队列深度。
3. 策略0-5 可以运行在真实 UDP 业务流上，发送端把策略字段叠加到 `iperf -u` 业务包中，接收端能够解码恢复并继续转发原始业务载荷。
4. P4 交换机只负责转发、路径调度和 INT；隐蔽载荷由终端侧 Python 程序处理。

### 阶段2：后续强化学习目标

阶段2再把 INT 结果输入控制平面，让 PPO 根据实时链路状态为每条链路选择策略。当前代码保留 PPO/仿真模块，但中期验证不依赖它。

## 2. 系统拓扑

```text
h1 -- s1 == path0/path1/path2 == s2 -- h2

h1: 10.0.1.1
h2: 10.0.1.2
s1 thrift: 9090
s2 thrift: 9091
```

三条链路默认配置：

| 路径 | 端口 | 默认时延 |
|---|---|---:|
| path0 | s1-eth2 <-> s2-eth2 | 5ms |
| path1 | s1-eth3 <-> s2-eth3 | 15ms |
| path2 | s1-eth4 <-> s2-eth4 | 30ms |

两台交换机运行同一个 P4 文件：

```text
p4/covert_int_switch.p4
```

不同角色通过流表和寄存器区分：

```text
p4/s1_commands.txt
p4/s2_commands.txt
```

## 3. P4 数据平面

### 3.1 主要职责

P4 程序当前承担四件事：

1. IPv4 LPM 普通转发。
2. 跨 s1-s2 链路的路径选择：默认、固定、轮询、冗余。
3. 真实业务包 inline INT 插入、终点剥离恢复和本地报告转换。
4. 维护端口级累计寄存器，供 INT 报告计算链路状态。

P4 不负责隐蔽数据编解码，也不解析任何隐蔽策略字段；它只按寄存器配置做路径调度、转发和 INT。

### 3.2 路径调度模式

| 模式 | `reg_path_mode` | 说明 |
|---|---:|---|
| 默认路由 | 0 | 使用 `ipv4_lpm` 表决定出端口。 |
| 固定链路 | 1 | 使用 `reg_fixed_path` 指定 path0/1/2。 |
| 轮询链路 | 2 | 每 `reg_rr_burst_size` 个包切换一次路径。 |
| 冗余链路 | 3 | 使用 BMv2 multicast group 把同一个包复制到三条链路。 |

典型轮询配置：

```text
register_write reg_path_mode 0 2
register_write reg_rr_burst_size 0 12
register_write reg_rr_counter 0 0
register_write reg_rr_current_path 0 0
```

`reg_rr_burst_size=12` 表示每条链路连续发送 12 个包后切换到下一条链路。这个值后续可以根据策略窗口长度调整。

## 4. INT 实现

### 4.1 当前选择：真实业务包 inline INT

当前阶段采用“真实业务包 inline INT + 终点交换机本地报告”的方式：

```text
h2 业务包 -> s2 采样插入 INT -> s2-s1 链路携带 INT
          -> s1 补齐 probe_data -> 本地复制两份
          -> rid=0：剥离 INT，恢复原业务包交给 h1
          -> rid=1：转换为 UDP/50100 INT 报告交给 h1 解析程序
```

这样 INT 头只在两台 P4 交换机之间短暂存在，h1/h2 的普通应用不会收到带 INT 头的业务包。UDP/50100 报告只由终点交换机本地送给解析程序，不再作为第二条遥测流穿过三条 s1-s2 链路。

### 4.2 INT 报文结构

采样命中的真实业务包在交换机间携带：

```text
Ethernet | IPv4(protocol=0xFD) | INT shim | probe_data[hop_count] | 原业务负载
```

INT shim 长度为 12 字节，包含：

| 字段 | 说明 |
|---|---|
| `ver` | INT 版本。 |
| `rep` | 报告标记，inline 业务包正常使用 `rep=0`。 |
| `hop_meta_len` | 每跳遥测长度，当前为 48 字节。 |
| `hop_count` | 已携带的 probe_data 数量。 |
| `original_protocol` | 记录原 IPv4 协议号，终点交换机剥离 INT 时恢复。 |
| `original_total_len` | 记录原 IPv4 长度，终点交换机剥离 INT 时恢复。 |
| `trace_id` | 每路径递增序号，用于丢包估计。 |

每跳 `probe_data` 固定 48 字节：

| 字段 | 说明 |
|---|---|
| `swid` | 交换机 ID。 |
| `port_ingress` / `port_egress` | 入端口和出端口。 |
| `byte_ingress` / `byte_egress` | 入/出端口累计字节快照。 |
| `count_ingress` / `count_egress` | 入/出端口累计包数快照。 |
| `last_time_ingress` / `last_time_egress` | 上次 INT 时间戳。 |
| `current_time_ingress` / `current_time_egress` | 本次 INT 时间戳。 |
| `qdepth` | 出端口队列深度。 |

### 4.3 INT 流水线

1. 所有 IPv4 包经过 ingress/egress 时都会更新累计字节和包数寄存器。
2. INT source 按 `reg_int_interval_us` 判断是否到达采样时间。
3. 到达采样时间时，source 在当前真实业务包内插入 INT shim 和第一跳 probe_data，并保存原始 IPv4 `protocol/totalLen`。
4. 该业务包携带 INT 通过实际选择的 s2-s1 链路。
5. terminal 收到 INT 业务包后补充本端 probe_data，并使用本地 multicast group 101 复制两份。
6. `egress_rid=0` 的副本剥离 INT，恢复原始 IPv4 字段后交给 h1；`egress_rid=1` 的副本转换为 UDP/50100 INT 报告。
7. Python 接收端解析 UDP/50100 报告，按连续快照差值计算链路状态。

默认中期验证方向是 h2->h1：s2 作为 INT source，s1 作为 INT terminal，h1 解析报告。

### 4.4 指标计算

链路状态由 `python/control_plane/int_parser.py` 和相关计算逻辑解析。核心思路是比较连续两个报告的差值：

| 指标 | 计算思路 |
|---|---|
| 时延 | terminal 入端时间减 source 出端时间。 |
| 抖动 | 相邻两次时延差的绝对值。 |
| 丢包率 | 根据每路径 INT 序号或包计数差估算。 |
| 相对带宽负载 | 使用累计字节差除以时间差，阶段1作为相对趋势指标。 |
| 队列深度 | 使用报告中的 `qdepth`。 |

阶段1测试报告见：

```text
int-test/INT测试报告.md
int-test/results/summary.csv
int-test/results/summary.json
```

当前测试覆盖单路 path0/path1/path2、多路轮询、不同延迟和 10% 丢包场景。18 条链路记录均有 INT 样本，业务 `iperf` 未中断。

## 5. 终端侧隐蔽策略

### 5.1 总体原则

隐蔽策略由终端 Python 完成，P4 不解析隐蔽数据：

```text
发送端 Python：读取隐蔽数据 -> 选择策略 -> 修改业务流时序/字段/包长
P4 交换机：只转发、调度路径、采集 INT
接收端 Python：从业务流中提取策略特征 -> 解码隐蔽数据
```

当前已经完成真实 UDP 业务流挂载闭环的是策略0-5。统一代理为 `experiments/udp_covert_proxy.py`：发送端代理接收本机业务 UDP 包，把策略字段叠加到这些业务包上；接收端代理抓包、识别当前策略、解码隐蔽数据，再还原原始业务 payload 并转发给本机 `iperf` server。

### 5.2 统一接收分发器

接收端新增统一策略分发器：

```text
python/receiver/strategy_router.py
```

它把抓包程序得到的包统一表示为：

```text
payload + metadata
```

其中 metadata 至少可以包含 `ip_id`、`packet_length`、`arrival_time_ms`、`path_id`、`dport`、`sequence_num` 等字段。分发器不直接参与发包，也不修改业务流，只负责接收侧识别、缓冲和调用解码器。

当前识别优先级如下：

| 策略 | 识别依据 | 顺序恢复依据 |
|---:|---|---|
| 0 | UDP payload 前 2 字节时序同步标签 | 标签中的 `symbol_index` 和接收时间 `arrival_time_ms`。 |
| 1 | UDP payload 前 2 字节时序同步标签 | 标签中的 `symbol_index/phase` 和接收时间 `arrival_time_ms`。 |
| 2 | IPv4 ID 中的 `flag + strategy_id=2 + seq_mod` | 块内 `seq_mod`、块认证和可选 `fragment_id`。 |
| 3 | payload 前 12 字节加密统计同步小头 | 小头中的 `symbol_index/total_symbols/repeat_index`。 |
| 4 | IPv4 ID 中的 `flag + strategy_id=4 + frame_id + symbol_id` | `frame_id/symbol_id` 收集喷泉码符号。 |
| 5 | IPv4 ID 中的 `flag + strategy_id=5 + path_id + encrypted fragment_id` | `fragment_id` 划分三包窗口，窗口内 `path_id` 排列承载 2 bit。 |

也就是说，接收端不再需要人为提前指定“这个 pcap 只属于某个策略”。抓到一个混合流后，分发器先根据包内轻量自描述字段或同步小头分组，再对每个 `(strategy_id, message_key)` 调用对应策略的 `decode()`。普通业务包如果没有匹配这些格式，会被记录为 ignored，不进入隐蔽解码缓冲区。

当前验证脚本：

```bash
python3 experiments/verify_strategy_router.py
```

该脚本会混合策略0-5的承载包和普通业务噪声包，打乱输入顺序后交给分发器。输出：

```text
experiments/results/router_summary.json
experiments/results/router_trace.csv
experiments/results/router_decoded/
```

当前 VM 结果为 6 个策略全部成功解码，24 个普通业务噪声包被忽略。需要注意：这一步验证的是接收侧分发与解码框架；真实业务流闭环部署现在由 `experiments/udp_covert_proxy.py`、`experiments/run_rule_proxy_closed_loop.py` 和五窗口 `topology_service.py` 负责，发送端用 `iperf -u` 产生真实业务包，代理层在这些业务包上挂载策略字段。

### 5.3 全局会话切块与乱序重组

统一接收分发器解决的是“这个包属于哪个策略、应该交给哪个 decode()”。但是最终隐蔽数据还需要跨策略按顺序恢复，因此新增全局会话层：

```text
python/covert_strategies/session.py
```

发送端先把原始隐蔽数据切成全局 chunk，每个 chunk 的帧格式为：

```text
magic/version/session_id/chunk_id/total_chunks/payload_len/header_len/crc32/payload
```

然后每个 chunk 可以交给不同策略和不同路径发送。接收端流程如下：

```text
抓包
 -> StrategyReceiverRouter 自动识别策略
 -> 对每个策略分组调用 decode()
 -> 得到若干全局 chunk
 -> CovertSessionAssembler 按 chunk_id 重组
 -> decoded_secret.bin
```

这样乱序问题分两层解决：

1. 策略内部按自己的字段恢复局部顺序，例如策略2用 `seq_mod`，策略4用 `frame_id/symbol_id`，策略0/1用同步标签和到达时间。
2. 全局会话层按 `chunk_id` 重排不同策略解出的数据块。

当前中期验证脚本：

```bash
python3 experiments/verify_manual_policy_session.py
```

默认手动策略计划为：

| 分配 | 策略 | 说明 |
|---|---:|---|
| path0 | 0 | 相对时序。 |
| path1 | 2 | 可靠 IP-ID。 |
| path0+path1 | 4 | IP-ID 喷泉码多路径协同。 |
| path2 | 3 | 包长统计。 |

策略4需要特别注意：它不是单路径策略，至少要绑定两条路径。脚本会校验这一点，如果把策略4配置为单路径会直接报错。

当前 VM 离线结果：95 字节隐蔽数据切成 12 个全局 chunk，不同 chunk 分别走策略0/2/4/3，最终 `hidden_match=true`。输出文件：

```text
experiments/results/manual_policy/summary.json
experiments/results/manual_policy/chunk_assignments.csv
experiments/results/manual_policy/decoded_secret.bin
```

真实 Mininet/BMv2 的手动计划 live 验证入口为：

```bash
sudo python3 experiments/run_manual_policy_live.py --timeout 60 --clean-results
```

该脚本用于阶段1的一体化演示：h2->h1 运行 UDP `iperf` 触发 INT，h1->h2 按全局 chunk 发送隐蔽数据，接收端统一分发后按 `chunk_id` 重组。live 主计划暂时使用更稳的三类策略：`path0 -> 策略2`、`path2 -> 策略3`、`path0+path1 -> 策略4`。其中策略4必须绑定至少两条路径，并通过 P4 的 `reg_path_mode=4` 加权轮询发送。六策略直接挂载到真实 UDP 业务流的验证由 `experiments/verify_udp_proxy_real_flow.py` 覆盖；策略0/1依赖包间隔，不适合把同一个时序窗口跨多条不同延迟链路轮询。

live 接收端对策略2有专门的乱序处理：根据 IP-ID 中的 `seq_mod` 序列恢复逻辑 `fragment_id`，同一个 `seq_mod` 的重复包不会推进块号，只有 `15 -> 0` 这类回绕才进入下一块。这样可以避免三次重复发送时把重复包误判为新片段。结果文件写入：

```text
experiments/results/manual_policy_live/
```

### 5.4 阶段二规则控制基线

阶段二的 PPO 接入点已经先用规则控制器跑通。核心文件为：

```text
python/control_plane/rule_policy_selector.py
experiments/run_stage2_rule_live.py
```

`RuleBasedPolicySelector` 的输入是 INT 输出的 `path_states`，输出是与手动计划相同格式的 `PolicyEntry` 列表。规则基线目前按时延、抖动、丢包和带宽负载给路径评分：低丢包、低抖动链路优先使用策略3；丢包或抖动较高时使用策略2；只要至少两条链路可用，就附加一个策略4多路径喷泉码协同项。

验证命令：

```bash
sudo python3 experiments/run_stage2_rule_live.py --timeout 60 --clean-results
```

脚本分两轮执行：第一轮运行 live 业务流并采集 INT；第二轮根据第一轮 INT 结果生成 `rule_plan.json`，再让发送端和接收端按该计划执行。当前 VM 结果为 `success=true`、`rule_hidden_match=true`、`rule_iperf_ok=true`、`rule_int_success=true`。后续 PPO 只要输出同样格式的计划文件，即可替换规则控制器。

### 5.5 交互式中期闭环

交互式闭环脚本把拓扑、业务流、INT、规则选策略、隐蔽发送和接收重组放在一个入口中：

```bash
sudo python3 experiments/run_interactive_closed_loop.py --clean-results
```

运行后，脚本启动 h2->h1 UDP `iperf` 作为持续业务流，并由 s2 触发反向 INT；h1 侧 `reverse_probe_receiver.py` 每秒写出最新 `path_states`。该脚本保留为历史兼容入口。当前推荐的一体化闭环是 `run_rule_proxy_closed_loop.py` 和五窗口 `topology_service.py`：它们使用 `udp_covert_proxy.py plan-sender/plan-receiver`，把策略0-5直接挂载到真实 `iperf -u` 业务包上。

非交互复测命令：

```bash
sudo python3 experiments/run_interactive_closed_loop.py \
  --clean-results \
  --demo-once "MIDTERM CLOSED LOOP TEST 1234567890" \
  --timeout 60
```

当前 VM 已验证：`success=true`、`iperf_ok=true`、`int_success=true`，h2 恢复文本与 h1 输入一致。为了保证中期演示稳定，live 主体使用策略2、策略3和策略4；六策略真实 UDP 业务流挂载由 `udp_covert_proxy.py` 和 `verify_udp_proxy_real_flow.py` 单独验证通过。

### 5.6 五窗口用户演示架构

为了便于中期现场演示，项目新增 `experiments/user_demo/`。该目录把交互式闭环拆成五个面向用户的窗口程序：

| 程序 | 技术作用 |
|---|---|
| `topology_service.py` | 用 sudo 持有 Mininet/BMv2 拓扑，启动后台业务流和 INT 解析器，并提供本地 JSON API。 |
| `sender_window.py` | 发送端窗口，调用服务的 `send` 接口提交隐蔽文本。 |
| `receiver_window.py` | 接收端窗口，轮询服务的解码历史并实时显示 h2 恢复结果。 |
| `link_status_window.py` | 链路状态窗口，轮询 `status` 接口显示三路径 INT 指标和建议策略计划。 |
| `link_config_tool.py` | 链路配置工具，调用 `set_links` 接口动态设置 path0/path1/path2 的 netem delay/loss。 |

服务端口默认为 `127.0.0.1:38765`。拓扑服务复用 `mininet_runtime.py`、`reverse_probe_receiver.py`、`udp_covert_proxy.py plan-sender/plan-receiver` 和 `RuleBasedPolicySelector`。发送过程是：读取最新 INT 状态 -> 生成规则策略计划 -> 写出 `proxy_plan.json` -> h2 启动 `plan-receiver` 和 `iperf -s -u` -> h1 启动 `plan-sender` 并用本机 `iperf -u` 产生真实业务包 -> 按分段切换 s1 路径模式 -> h2 代理识别策略、解码隐蔽数据并把原始 payload 转发给 `iperf` server。

当前 VM 已完成五窗口服务级联调：

| 场景 | INT/链路状态 | 隐蔽输入 | 结果 | 实际计划 |
|---|---|---|---|---|
| 默认链路 | path0/path1/path2 均有 INT 样本 | `MIDTERM_PROXY_FLOW_六策略真实业务流闭环测试_0123456789` | `success=true`，`hidden_match=true`，反向 `iperf` 与 INT 持续运行 | `S0@[0] | S1@[1] | S3@[2] | S4@[0,1,2] | S5@[0,1,2] | S2@[0]` |
| 修改链路 | `1 60 8 2 10 0 3 25 2` 后，INT 解析到 path0 约 60ms/5.8% 丢包、path1 约 10ms/0%、path2 约 25ms/1% | `AFTER_LINK_CHANGE_自动规则切换验证_abcdef0123456789` | `success=true`，`hidden_match=true`，策略计划随链路状态变化 | `S0@[0] | S1@[1] | S3@[1] | S2@[0] | S4@[1,2,0] | S5@[0,1,2]` |

### 5.7 策略0：高隐蔽相对时序

策略0用两个连续间隔的大小关系表示 1 bit：

```text
短间隔 + 长间隔 -> 0
长间隔 + 短间隔 -> 1
```

特点：

- 不依赖绝对阈值，对慢变时延漂移更稳。
- 容量较低，但隐蔽性相对更好。
- 适合低抖动链路。

### 5.8 策略1：高容量排序时序

策略1用三个连续间隔的排序表示 2 bit：

```text
三个间隔的相对大小排序 -> 一个 2 bit 符号
```

特点：

- 容量高于策略0。
- 需要更稳定的链路质量。
- 当前已修复首窗口 anchor 缺失时可能误判 unknown 的问题：完整三间隔优先；如果 anchor 或上一符号末包缺失，但当前窗口三个相位包完整，则用窗口内部两个间隔反推排序。

### 5.9 方案B：两字节同步标签

策略0/1本身依赖时序，如果网络中丢失一个参与隐蔽承载的包，传统做法容易导致后续窗口整体错位。当前采用方案B：

```text
UDP payload 前 2 字节 = 同步标签
后续 payload = 原始业务数据
```

同步标签字段经过轻量异或混淆，包含：

```text
frame_id      隐蔽帧编号
strategy_id   策略编号
phase         窗口内相位或 anchor
symbol_index  bit/symbol 索引
```

标签只用于识别和重同步，真正隐蔽比特仍由时序承载。接收端如果发现某个窗口缺包，只标记局部 `unknown_bits` 或 `unknown_symbols`，不会让后续全部错位。

相关文件：

```text
python/covert_strategies/timing_sync_tag.py
python/covert_strategies/timing_high_covert.py
python/covert_strategies/timing_high_capacity.py
experiments/udp_covert_proxy.py
```

### 5.10 真实 UDP 业务流代理

为了避免“单独发策略包”的不真实问题，当前使用 UDP 代理把策略0-5挂到 `iperf -u` 业务流上：

```text
h1 iperf -u client
  -> h1 sender proxy
  -> s1/s2 P4 多路径与 INT
  -> h2 receiver proxy
  -> h2 iperf -u server
```

发送端代理接收真实业务包，然后按策略叠加不同特征：策略0/1控制包间隔并加 2 字节同步标签；策略2/4/5写 IPv4 ID；策略3加入同步小头并调节 IP 包长。接收端代理抓取这些业务包，按当前策略精确识别并解码，最后剥离代理层字段，把原始 UDP payload 交给 `iperf` 服务端。

最新闭环结果见：

```text
experiments/results/udp_proxy_real_flow/summary.json
experiments/results/udp_proxy_real_flow/strategy_0/
...
experiments/results/udp_proxy_real_flow/strategy_5/
```

最新 VM 复测结果：

| 策略 | 隐蔽输入 | 隐蔽输出 | 隐蔽比对 | receiver 成功 | 转发业务包 | iperf server收到业务 |
|---:|---|---|---|---|---:|---|
| 0 | `A` | `A` | true | true | 636 | true |
| 1 | `B` | `B` | true | true | 643 | true |
| 2 | `S2-OK` | `S2-OK` | true | true | 750 | true |
| 3 | `S3-OK` | `S3-OK` | true | true | 752 | true |
| 4 | `S4-OK` | `S4-OK` | true | true | 750 | true |
| 5 | `S5-OK` | `S5-OK` | true | true | 752 | true |

## 6. 其他策略状态

| 策略 | 当前状态 | 后续工作 |
|---|---|---|
| 策略2 IP-ID 存储型 | 已升级为可靠块编码：`flag + strategy_id + seq_mod + encrypted_value`，支持乱序重组、XOR 轻量恢复和块认证。 | 已接入真实 UDP 业务流代理；后续可继续做抓包分布伪装。 |
| 策略3 包长统计型 | 已升级为统计分布包长信道，支持数据白化、伪随机区间映射、加密同步小头、三次重复投票和乱序重排。 | 已接入真实 UDP 业务流代理；使用时需要控制业务 payload 长度，避免接近 MTU。 |
| 策略4 IP-ID 喷泉码多路径协同 | 已实现 IP-ID 喷泉码、接收端 GF(2) 解码和 P4 加权轮询。 | 已接入真实 UDP 业务流代理；必须绑定两条或三条路径，不能单路径单独使用。 |
| 策略5 多路径路径序列 | 已实现路径排列窗口编码，三包窗口承载 2 bit，IP-ID 做轻量自描述和 path hint。 | 已接入真实 UDP 业务流代理；P4 用 `reg_path_mode=5` 按 path hint 控制路径，代理层重复挂载提升抗轻微丢包能力。 |

## 7. 验证命令

阶段1相关单元测试：

```bash
python3 -m unittest tests.test_strategies -v
```

启动拓扑：

```bash
sudo bash run.sh
```

INT 详细验证：

```text
int-test/操作文档.md
```

六策略真实 UDP 业务流验证：

```bash
sudo python3 experiments/verify_udp_proxy_real_flow.py \
  --strategies 0,1,2,3,4,5 \
  --iperf-time 5 \
  --case-timeout 35 \
  --iperf-rate 180K \
  --iperf-len 200 \
  --clean-results
```

## 8. 当前限制

1. 策略0/1使用 2 字节同步标签，严格意义上会在代理间 UDP payload 中留下额外字段；中期阶段先强调“真实业务流承载”和“业务不受影响”，后续再做更强的字段伪装。策略0/1对丢包和抖动敏感，当前验证使用低速短消息和重复挂载。
2. INT 的带宽结果当前更适合作为相对负载指标，精确带宽计量需要更长时间窗口和更稳定的采样。
3. PPO 相关测试依赖 `torch/gymnasium`，当前 VM 未安装这些阶段2依赖；阶段1测试不依赖它们。

### 阶段1一体化闭环说明

当前已经验证的完整闭环是：策略0-5 都可以挂载到真实 UDP 业务流从 h1 发往 h2；h2 侧代理解码隐蔽数据后继续把业务 payload 交给 `iperf` server。h2 到 h1 的反向业务流由 s2 轮询三条路径并触发 INT，h1 接收 UDP/50100 报告后得到 path0/path1/path2 的链路状态。不要在阶段1把同一个策略0/1时序窗口直接轮询到三条不同延迟路径，否则多路径时延差会破坏包间隔关系。

最新一体化结果见：`proxy-test/full_stage1_results_fixed/summary.json`。

## 9. 策略2可靠 IP-ID 存储信道

策略2的目标是抗丢包和抗乱序，适合时延抖动较大、不适合策略0/1时序信道的链路。当前 IP-ID 候选头格式为：

```text
bit15       covert_flag = 1
bits14-12   strategy_id = 2
bits11-8    seq_mod，块内序号 0~15
bits7-0     encrypted_value
```

单个 IP-ID 只做候选识别，不能直接当成有效隐蔽数据。接收端必须按块收集并通过认证：

```text
seq_mod 0~11     12 字节数据
seq_mod 12~14    3 字节 XOR 冗余，每 4 个数据字节对应 1 个校验
seq_mod 15       1 字节 block_auth
```

接收端处理流程：

1. 读取业务包 IP-ID，筛选 `covert_flag=1` 且 `strategy_id=2` 的候选包。
2. 根据 `seq_mod` 放回块内位置，不依赖包到达顺序。
3. 如果某个 4 字节 XOR 组内丢失 1 个数据片段，且对应 parity 存在，则恢复该数据字节。
4. 使用 `block_auth` 校验整块，认证通过后才输出 12 字节数据。
5. 多个块按 `block_id` 顺序拼接，再解析 `P2 + length + payload` 帧头恢复原始隐蔽数据。

当前实现中 `block_id` 由发送端片段序号或接收端缓冲窗口推断；在仿真和测试接口中使用 `fragment_id` 提供确定块号。后续接入真实抓包时，如果要跨多个块强抗乱序，可以在控制层为策略2发送端和接收端增加更明确的块同步包或小范围滑动匹配。

本方案解决的次序问题是：策略2不按到达顺序拼接，而按 `block_id + seq_mod` 重排；普通业务包误判问题由整块认证过滤；轻微丢包由 XOR parity 恢复。


### 5.6 策略2：高可靠 IP-ID 存储信道

策略2用于丢包较明显的链路。发送端通过 Scapy 二层发包显式设置 IPv4 Identification 字段，P4 交换机仍只负责普通转发和路径调度。

当前字段为 `covert_flag + strategy_id + seq_mod + encrypted_value`。`encrypted_value` 解密后包含 `block_mod + data_nibble`。每个块包含 12 个数据半字节、3 个 XOR 冗余半字节、1 个认证半字节，并默认把每个逻辑片段重复发送 3 次。

最新 live 矩阵见 `celue2/测试报告.md`：64 字节输入生成 576 个承载包，在约 0%~32% 实际丢包范围内均可完整恢复。


### 5.7 策略3：统计分布包长信道

策略3不再是固定“某个包长表示某个符号”的简单方案。当前版本先对白化后的隐蔽数据按 2 bit 切分，再使用密钥驱动的伪随机置换把符号映射到 4 个合法包长区间。每个包的具体长度在区间内部伪随机选择，避免固定长度过于显眼。

为解决接收端乱序和轻微丢包，策略3在 payload 前部放置 12 字节加密同步小头，包含帧号、符号序号、总符号数、总 bit 数和重复轮次。每个符号默认发送 3 次，接收端按 `symbol_index` 聚合后进行软投票。

当前单元测试覆盖：正常解码、乱序重排、丢失一个重复轮仍可解码、同步小头认证失败过滤。离线说明见 `celue3/操作说明.md`。

## 10. 策略4 IP-ID 喷泉码多路径协同

策略4用于三条链路都较差时的多路径协同承载。终端 Python 把每个隐蔽数据 frame 切成 4 bit 源符号，生成喷泉码 symbol，并写入 IPv4 Identification 字段：

```text
bit15       flag = 1
bits14-12   strategy_id = 4
bits11-8    frame_id
bits7-4     symbol_id
bits3-0     encrypted coded_nibble
```

当前 live 参数为 `k=4, num_output=16`。`k<=4` 时使用固定高秩组合表生成 symbol，减少高丢包下 frame 秩不足的问题。P4 只负责 `reg_path_mode=4` 的加权轮询，不使用 UDP 端口、DSCP、TTL 标记路径。

验证命令：

```bash
sudo python3 celue4/run_strategy4_matrix.py --timeout 15
```

最新结果见 `celue4/测试报告.md`：6/6 场景均成功解码，包含两路径 path1 30% 丢包、三路径均 10% 丢包等场景。
## 11. 策略5多路径路径序列信道

策略5把路径选择本身作为隐蔽载体。发送端把数据切成 2 bit 符号，每个符号映射成一个三路径排列窗口：

```text
00 -> path0, path1, path2
01 -> path0, path2, path1
10 -> path1, path0, path2
11 -> path1, path2, path0
```

接收端根据 `fragment_id` 或接收窗口重组出三包窗口，再由路径元数据或路径特征恢复排列。它的优势是 IP-ID 只做轻量自描述，真实隐蔽比特仍藏在路径排列中；限制是需要发送端/控制面能够按窗口控制实际路径。当前 `celue5/run_strategy5_matrix.py` 已完成 100 bit 离线矩阵验证：顺序和乱序完整恢复，数据区少量缺包只造成局部 unknown，帧头区缺包会触发 magic 校验失败。
