# 中期审核验证说明

本文档按当前 VM `/home/p4/yws-covert` 中已经跑通的阶段1版本整理。中期审核建议把重点放在“拓扑能通、业务不断、INT 能测、能够按 INT 状态生成策略计划并恢复隐蔽数据；策略0-5 都能挂载到真实 UDP 业务流上并完成接收端解码”。

## 1. 当前演示目标

1. 启动 `h1 -- s1 == 三条链路 == s2 -- h2` 的 BMv2/P4 拓扑。
2. 证明 h1/h2 普通业务通信正常，`ping` 和 `iperf` 不因 INT 中断。
3. 证明 INT 能得到三条链路状态。
4. 证明 h1 输入隐蔽数据后，系统可以根据 INT 状态生成规则策略计划，并由 h2 按策略分发、解码、按序重组。
5. 证明策略0-5 都能挂在真实 `iperf -u` 业务流上完成隐蔽数据传输和接收端解码。
6. 说明 PPO 是阶段2工作，中期先用规则选择器替代 PPO 输出策略计划。

## 2. 关键文件

| 文件/目录 | 作用 |
|---|---|
| `run.sh` | 编译 P4、启动 Mininet/BMv2、下发 s1/s2 流表。 |
| `p4/covert_int_switch.p4` | 单文件 P4 程序，包含转发、路径调度和 INT。 |
| `p4/s1_commands.txt` | s1 默认表项和寄存器配置。 |
| `p4/s2_commands.txt` | s2 默认表项和寄存器配置。 |
| `experiments/reverse_probe_receiver.py` | h1 侧 INT 报告解析程序。 |
| `experiments/udp_covert_proxy.py` | 策略0-5 统一真实 UDP 业务流代理。 |
| `experiments/verify_udp_proxy_real_flow.py` | 六策略真实 UDP 业务流挂载自动验证脚本。 |
| `experiments/run_rule_proxy_closed_loop.py` | 当前推荐的一键真实业务流闭环验证：INT、规则选策略、六策略代理挂载、业务流转发。 |
| `experiments/run_dynamic_rule_proxy_closed_loop.py` | 长消息在线动态切换验证：传输中改变链路状态，后续 segment 自动换策略/路径。 |
| `experiments/run_interactive_closed_loop.py` | 历史兼容交互脚本：自动启动拓扑、业务流、INT、规则选策略和收发重组。 |
| `experiments/user_demo/` | 五窗口用户演示程序：拓扑服务、发送、接收显示、链路状态、链路设置。 |
| `python/receiver/strategy_router.py` | 统一策略接收分发器，负责混合流识别、分组和解码调用。 |
| `experiments/verify_strategy_router.py` | 统一接收分发器离线闭环验证脚本。 |
| `python/covert_strategies/session.py` | 全局隐蔽会话切块和按序重组。 |
| `experiments/verify_manual_policy_session.py` | 手动策略计划下的多策略全局会话闭环验证。 |
| `int-test/` | INT 验证说明、报告和结果。 |
| `proxy-test/` | 早期策略0/1真实 UDP 业务流代理说明、报告和结果。 |

## 3. 启动拓扑

进入虚拟机：

```bash
cd /home/p4/yws-covert
sudo bash run.sh
```

`run.sh` 会做这些事：

1. 清理旧 Mininet/BMv2 状态，删除上次异常退出留下的 veth 接口和 simple_switch 残留，避免 `RTNETLINK answers: File exists`。
2. 编译 `p4/covert_int_switch.p4` 到 `p4/covert_int_switch.json`。
3. 启动 h1、h2、s1、s2 和三条 s1-s2 链路。
4. 关闭虚拟网卡 offload。
5. 设置 MTU：终端侧 1500，交换机间链路 1600。
6. 下发 `p4/s1_commands.txt` 和 `p4/s2_commands.txt`。

进入 Mininet CLI 后先检查：

```bash
h1 ping -c 5 10.0.1.2
h2 ping -c 5 10.0.1.1
```

## 4. 五窗口用户演示

中期现场最推荐使用五窗口演示方式。它把“拓扑服务、发送端、接收端、链路状态、链路设置”分开，更接近最终系统形态。

窗口1：启动拓扑服务。该窗口需要 `sudo`，启动后保持运行。服务启动前会自动清理旧 Mininet/BMv2 残留；如果 `127.0.0.1:38765` 被旧五窗口服务占用，会先尝试请求旧服务退出，再启动新的拓扑。

```bash
cd /home/p4/yws-covert
sudo python3 experiments/user_demo/topology_service.py --clean-results
```

窗口2：接收端实时显示 h2 解码结果。

```bash
cd /home/p4/yws-covert
python3 experiments/user_demo/receiver_window.py
```

窗口3：动态显示 h1 解析出的 INT 三路径状态，以及规则选择器建议的策略。

```bash
cd /home/p4/yws-covert
python3 experiments/user_demo/link_status_window.py
```

窗口4：发送端输入隐蔽数据。输入文本并回车后，h1 会按当前 INT 状态生成策略计划并发送，h2 解码结果会显示在窗口2。

```bash
cd /home/p4/yws-covert
python3 experiments/user_demo/sender_window.py
```

窗口5：按需修改链路状态。

```bash
cd /home/p4/yws-covert
python3 experiments/user_demo/link_config_tool.py
```

也可以一次性设置：

```bash
python3 experiments/user_demo/link_config_tool.py 1 20 10 2 10 20 3 30 30
```

含义是：链路1 delay=20ms/loss=10%，链路2 delay=10ms/loss=20%，链路3 delay=30ms/loss=30%。恢复默认：

```bash
python3 experiments/user_demo/link_config_tool.py 1 5 0 2 15 0 3 30 0
```

五窗口演示的结果统一保存在：

```text
experiments/results/user_demo/
```

当前五窗口发送入口已经使用真实 UDP 业务流代理，并升级为 chunk 级动态重规划：窗口4输入文本后，h1 先启动本机 `iperf -u` 业务流喂给 `plan-sender`；每个 segment 开始前，服务读取最新 INT 链路状态，为该 segment 重新选择策略/路径并改写 `proxy_plan.json`，然后才放行业务包。h2 的 `plan-receiver` 会动态重新加载计划，解码隐蔽数据后把原始业务 payload 转发给本机 `iperf -s -u`。窗口2显示解码结果，窗口3继续显示 INT 状态和当前运行策略，窗口5可在发送过程中动态修改链路。

当前 VM 已验证两组服务级场景：

| 场景 | 输入 | 结果 | 策略计划 |
|---|---|---|---|
| 默认链路 | `MIDTERM_PROXY_FLOW_六策略真实业务流闭环测试_0123456789` | `success=true`，`hidden_match=true`，INT 与反向 `iperf` 持续运行 | `S0@[0] | S1@[1] | S3@[2] | S4@[0,1,2] | S5@[0,1,2] | S2@[0]` |
| 修改链路 `1 60 8 2 10 0 3 25 2` | `AFTER_LINK_CHANGE_自动规则切换验证_abcdef0123456789` | `success=true`，`hidden_match=true` | `S0@[0] | S1@[1] | S3@[1] | S2@[0] | S4@[1,2,0] | S5@[0,1,2]` |

长消息中途切换的自动化复测命令：

```bash
sudo python3 experiments/run_dynamic_rule_proxy_closed_loop.py \
  --clean-results \
  --timeout 140 \
  --iperf-rate 260K \
  --iperf-len 200
```

该脚本会在隐蔽消息传输中主动改变三条链路的 delay/loss，验证后续 segment 是否根据最新 INT 状态切换策略和路径。当前 VM 结果文件为：

```text
experiments/results/dynamic_rule_proxy_closed_loop/summary.json
```

关键结果：`success=true`、`hidden_match=true`、`all_six_strategies_seen=true`、`strategy_changed_after_network_change=true`、`path_changed_after_network_change=true`、`int_success=true`、`iperf_server_received=true`。切换粒度是 chunk/segment 边界，不是包级任意切换。

## 5. 一键交互式闭环演示

如果只想用一个窗口做自动复测，可以跑这个入口：

```bash
cd /home/p4/yws-covert
sudo python3 experiments/run_interactive_closed_loop.py --clean-results
```

脚本会自动完成以下动作：

1. 编译并启动 `h1 -- s1 -- 三条链路 -- s2 -- h2` 拓扑。
2. 后台启动 h2->h1 UDP `iperf`，让业务流持续存在并触发 INT。
3. h1 启动 INT 报告解析器，周期性写出最新三路径状态。
4. 在终端等待你输入隐蔽文本，回车后立即发送。
5. h1 根据最新 INT 状态生成规则策略计划，短文本走最优单路径，长文本切成全局 chunk 后多策略发送。
6. h2 抓包、识别策略、解码 chunk，并按 `chunk_id` 重组，终端直接显示恢复出的文本。

退出时输入：

```text
/quit
```

非交互复测命令：

```bash
sudo python3 experiments/run_interactive_closed_loop.py \
  --clean-results \
  --demo-once "MIDTERM CLOSED LOOP TEST 1234567890" \
  --timeout 60
```

结果文件：

```text
experiments/results/interactive_closed_loop/summary.json
experiments/results/interactive_closed_loop/history.csv
experiments/results/interactive_closed_loop/session_XXX/summary.json
experiments/results/interactive_closed_loop/session_XXX/rule_plan.json
experiments/results/interactive_closed_loop/session_XXX/send_manifest.csv
experiments/results/user_demo/session_XXX/proxy_plan.json
experiments/results/user_demo/session_XXX/sender_summary.json
experiments/results/user_demo/session_XXX/receiver_summary.json
experiments/results/interactive_closed_loop/session_XXX/decoded_secret.bin
```

当前 VM 已验证：`--demo-once "MIDTERM CLOSED LOOP TEST 1234567890"` 运行成功，`summary.json` 中 `success=true`、`iperf_ok=true`、`int_success=true`，h1 解析到 path0/path1/path2，h2 解码文本与输入一致。

## 6. INT 功能验证

当前 INT 默认验证 h2->h1 方向：

```text
h2 -> s2 -> 三条链路之一 -> s1 -> h1
```

当前实现采用真实业务包 inline INT，但 INT 头只在两台交换机之间存在：

```text
s2 在采样业务包中插入 INT -> s1 补齐 probe_data
-> s1 剥离 INT 并恢复业务包交给 h1
-> s1 本地生成 UDP/50100 报告给 h1 解析程序
```

最小手动流程：

```bash
h1 python3 experiments/reverse_probe_receiver.py \
  --timeout 30 \
  --window-ms 30000 \
  --output experiments/results/manual_int_check.json &

h1 iperf -s -i 5 &
h2 iperf -c 10.0.1.1 -t 20 -i 5

h1 cat experiments/results/manual_int_check.json
```

重点看：

| 字段 | 含义 |
|---|---|
| `parsed_int_reports` | h1 成功解析的 INT 报告数量。 |
| `metric_sample_counts` | 每条路径的指标样本数量。 |
| `path_states` | 每条路径的状态。 |
| `delay_ms` | 实测时延。 |
| `loss_rate` | 实测丢包率。 |
| `bw_utilization` | 相对带宽负载。 |

完整 INT 测试报告：

```text
int-test/操作文档.md
int-test/INT测试报告.md
int-test/results/summary.csv
int-test/results/summary.json
```

已完成测试包括：三条单路径基础时延、单路径改时延、单路径 10% 丢包、多路径轮询、多路径某一路 10% 丢包、多路径不同时延组合。

## 7. 六策略真实 UDP 业务流验证

策略0-5不是单独发测试包，而是通过统一 UDP 代理挂到真实 `iperf -u` 业务流上：

```text
h1 iperf -u client
  -> h1 sender proxy
  -> s1/s2
  -> h2 receiver proxy
  -> h2 iperf -u server
```

统一验证命令：

```bash
cd /home/p4/yws-covert
sudo python3 experiments/verify_udp_proxy_real_flow.py \
  --strategies 0,1,2,3,4,5 \
  --iperf-time 5 \
  --case-timeout 35 \
  --iperf-rate 180K \
  --iperf-len 200 \
  --clean-results
```

该脚本会自动启动 Mininet/BMv2 拓扑，并逐个验证六个策略。每一轮都由 h1 的真实 `iperf -u` 业务包进入 sender proxy，proxy 在这些业务包上叠加隐蔽字段，经过 P4 拓扑到 h2 receiver proxy；receiver proxy 解码隐蔽数据后，会把原始 UDP payload 继续转发给 h2 的 `iperf -u` server。

不要把 UDP `iperf` 打满。当前验证用 `180K` 和 `-l 200` 是为了避免业务排队把时序阈值和包长策略一起扰乱；后续可以单独做高负载压力测试。

## 8. 最新复测结果

最新结果文件：

```text
experiments/results/udp_proxy_real_flow/summary.json
experiments/results/udp_proxy_real_flow/strategy_0/
experiments/results/udp_proxy_real_flow/strategy_1/
...
experiments/results/udp_proxy_real_flow/strategy_5/
```

结果摘要：

| 策略 | 隐蔽输入 | 隐蔽输出 | 隐蔽比对 | receiver 成功 | 转发业务包 | iperf server收到业务 |
|---:|---|---|---|---|---:|---|
| 0 | `A` | `A` | true | true | 636 | true |
| 1 | `B` | `B` | true | true | 643 | true |
| 2 | `S2-OK` | `S2-OK` | true | true | 750 | true |
| 3 | `S3-OK` | `S3-OK` | true | true | 752 | true |
| 4 | `S4-OK` | `S4-OK` | true | true | 750 | true |
| 5 | `S5-OK` | `S5-OK` | true | true | 752 | true |

当前 VM 复测结论：`success=true`，六个策略均完成真实 UDP 业务流挂载、隐蔽数据解码和业务 payload 转发。策略4在验证时使用 P4 加权轮询，不作为单路径策略使用。

规则自动切换真实业务流闭环复测入口：

```bash
sudo python3 experiments/run_rule_proxy_closed_loop.py \
  --clean-results \
  --timeout 85 \
  --iperf-rate 220K \
  --iperf-len 200
```

该脚本一次性验证“INT 获取链路状态 -> 规则选择策略/路径 -> 六策略挂载真实 `iperf -u` 业务流 -> h2 解码 -> 业务流不中断”。当前 VM 结果为 `success=true`、`all_six_strategies_seen=true`，两个场景均 `hidden_match=true`、`int_success=true`、`iperf_server_received=true`。该脚本暂不使用 PPO，使用 `RuleBasedPolicySelector` 作为阶段2前的规则基线。

阶段1相关单元测试：

```bash
python3 -m unittest tests.test_strategies -v
```

当前 VM 结果：41 个策略相关测试通过。

统一接收分发器验证：

```bash
python3 experiments/verify_strategy_router.py
```

该脚本混合策略0-5承载包和普通业务噪声包，验证接收端能够自动识别策略、按策略缓冲并调用对应解码器。结果文件：

```text
experiments/results/router_summary.json
experiments/results/router_trace.csv
experiments/results/router_decoded/
```

当前 VM 结果：6 个策略分组全部解码成功，24 个普通业务噪声包被忽略。

手动策略计划的全局会话闭环验证：

```bash
python3 experiments/verify_manual_policy_session.py
```

当前默认计划：

```text
path0 使用策略0
path1 使用策略2
path0+path1 使用策略4
path2 使用策略3
```

这里策略4必须至少绑定两条路径，因为它是 IP-ID 喷泉码多路径协同策略，不是单路径策略。该验证脚本会先把秘密数据切成带 `session_id/chunk_id/CRC` 的全局 chunk，再按手动计划交给不同策略发送；接收端通过统一分发器识别策略，最后按 `chunk_id` 重组。

当前 VM 结果：95 字节秘密数据切成 12 个 chunk，最终 `hidden_match=true`。结果文件：

```text
experiments/results/manual_policy/summary.json
experiments/results/manual_policy/chunk_assignments.csv
experiments/results/manual_policy/decoded_secret.bin
```

真实 Mininet/BMv2 手动策略闭环使用下面的入口：

```bash
sudo python3 experiments/run_manual_policy_live.py --timeout 60 --clean-results
```

该脚本会同时做三件事：h2->h1 运行 UDP `iperf` 触发 INT，h1->h2 发送按全局 chunk 切分的隐蔽数据，h2 侧统一接收分发并按 `chunk_id` 重组。中期演示版 live 计划使用 `path0 -> 策略2`、`path2 -> 策略3`、`path0+path1 -> 策略4`。策略4必须至少两条路径，不能单独作为某一条链路上的策略。六策略是否能直接挂载真实 UDP `iperf` 业务流，由 `experiments/verify_udp_proxy_real_flow.py` 统一验证；策略0/1依赖稳定包间隔，不适合把同一个时序窗口在三条不同延迟链路之间直接轮询。

live 接收端已经补充策略2的片段顺序推断：根据 IP-ID 的 `seq_mod` 处理三次重复发送和 `15 -> 0` 块回绕，避免重复包造成后续块整体错位。结果目录：

```text
experiments/results/manual_policy_live/
```

阶段二规则控制闭环验证：

```bash
sudo python3 experiments/run_stage2_rule_live.py --timeout 60 --clean-results
```

该验证先用业务流触发 INT 获取三条链路状态，再由 `RuleBasedPolicySelector` 自动生成策略计划，最后按该计划执行第二轮隐蔽数据发送和接收。当前 VM 结果：`success=true`、`rule_hidden_match=true`、`rule_iperf_ok=true`、`rule_int_success=true`。本次规则计划根据三条链路均低丢包、低抖动的状态，选择策略3作为主要承载，并生成策略4三路径喷泉码协同项作为后续高丢包场景的备用多路径策略。

结果目录：

```text
experiments/results/stage2_rule_live/
```

中期汇报时可以这样表述：目前 PPO 尚未正式训练，但 PPO 所需的输入输出链路已经打通，即 INT 链路状态可以进入控制平面，控制平面可以输出每条路径/每类 chunk 的策略计划，发送端和接收端可以按计划完成隐蔽数据恢复。

## 9. 路径切换命令

进入 s2 CLI：

```bash
simple_switch_CLI --thrift-port 9091
```

固定 path0：

```text
register_write reg_path_mode 0 1
register_write reg_fixed_path 0 0
register_write reg_int_probe_mode 0 1
register_write reg_int_fixed_probe_path 0 0
register_write reg_int_interval_us 0 10000
register_write reg_next_sample_time 0 0
register_write reg_int_enabled 0 1
```

固定 path1/path2 时，把 `reg_fixed_path` 和 `reg_int_fixed_probe_path` 改成 1 或 2。

轮询三路径：

```text
register_write reg_path_mode 0 2
register_write reg_rr_burst_size 0 12
register_write reg_rr_counter 0 0
register_write reg_rr_current_path 0 0
register_write reg_int_probe_mode 0 0
register_write reg_int_interval_us 0 10000
register_write reg_next_sample_time 0 0
register_write reg_int_enabled 0 1
```

## 10. 中期汇报建议表述

可以这样概括当前进度：

> 当前阶段已经完成 P4/BMv2 双交换机三链路拓扑、手动路径切换、基于真实业务包的 inline INT、三路径链路状态解析，以及策略0-5在真实 UDP `iperf` 业务流上的端到端隐蔽传输验证。接收端已新增统一策略分发器和全局会话重组层，可以从混合流中识别策略0-5并按 chunk 顺序恢复隐蔽数据。PPO 自动策略选择作为下一阶段工作，将复用当前 INT 输出的链路状态和 P4 路径控制接口。

### 阶段1一体化闭环说明

当前已经验证的完整闭环是：策略0-5 都可以通过 `experiments/udp_covert_proxy.py` 挂载到真实 UDP 业务流从 h1 发往 h2，h2 侧代理解码隐蔽数据后继续把原始业务 payload 交给 `iperf` server；h2 到 h1 的反向业务流由 s2 轮询三条路径并触发 INT，h1 接收 UDP/50100 报告后得到 path0/path1/path2 的链路状态。不要在阶段1把同一个策略0/1时序窗口直接轮询到三条不同延迟路径，否则多路径时延差会破坏包间隔关系。

最新一体化结果见：`proxy-test/full_stage1_results_fixed/summary.json`。

## 11. 策略2当前优化状态

策略2已经完成策略库级优化，重点解决抗丢包和乱序问题。当前版本使用 IP-ID 字段中的 `covert_flag + strategy_id + seq_mod + encrypted_value` 做候选标记，每 16 个承载包组成一个块，其中 12 个数据、3 个 XOR 冗余、1 个块认证。接收端按 `seq_mod` 重排，不依赖包到达顺序；认证不通过的块不会输出，从而降低普通业务包 IP-ID 偶然撞上格式造成的误判。

验证命令：

```bash
python3 -m unittest tests.test_strategies.TestProtocolHighReliability -v
python3 -m unittest tests.test_strategies -v
```

已覆盖：正常编解码、乱序重组、每个 XOR 组丢 1 个数据片段恢复、篡改 IP-ID 后块认证拒绝。策略2已经接入 `udp_covert_proxy.py`，并在六策略真实 UDP 业务流验证中通过。


## 12. 策略2验证

策略2当前已完成单路径 live 矩阵验证，适合作为“抗丢包策略”的中期补充展示。

```bash
cd /home/p4/yws-covert
sudo python3 celue2/run_strategy2_matrix.py --timeout 25
```

本轮测试中，64 字节隐蔽数据在 5ms/20ms/50ms 无丢包，以及 5%、10%、20%、30% 随机丢包设置下均成功恢复。结果见 `celue2/测试报告.md`、`celue2/results/summary.json` 和 `celue2/results/summary.csv`。


## 13. 策略3优化状态

策略3已完成策略库级优化：由简单包长映射升级为统计分布包长信道，支持数据白化、伪随机区间映射、加密同步小头、重复投票和乱序重排。当前已通过单元测试，后续可以参考策略2的 `celue2` 方式增加 live 矩阵测试。

```bash
python3 -m unittest tests.test_strategies.TestStatisticalFusion -v
```

说明文件：`celue3/操作说明.md`。

## 14. 策略4验证

策略4当前可作为“多路径协同抗丢包方案”展示。它把喷泉码 symbol 写入 IPv4 Identification 字段，P4 使用加权轮询把承载包分发到两条或三条链路，接收端按 `frame_id/symbol_id` 收集并解码。

```bash
cd /home/p4/yws-covert
sudo python3 celue4/run_strategy4_matrix.py --timeout 15
```

本轮 live 矩阵中，23 字节隐蔽数据生成 256 个承载包，在三路径等权、path2 20% 丢包、两路径 path1 30% 丢包、三路径均 10% 丢包等 6 个场景下均成功恢复；同时 h2->h1 UDP iperf 业务流未中断，INT 均解析到三条路径状态。结果见 `celue4/测试报告.md` 和 `celue4/results/summary.csv`。
## 15. 策略5设计补充

策略5用于展示“多路径本身也可以成为隐蔽载体”。它不改端口号，IP-ID 只做自描述，不直接写真实隐蔽比特；真实数据通过三包窗口内的路径排列表示 2 bit。当前已经完成 `celue5/run_strategy5_matrix.py` 离线矩阵验证：顺序和全局乱序均完整恢复，数据区少量缺包只造成局部 unknown，不会让后续码流整体错位。策略5也已经接入 `udp_covert_proxy.py`，通过真实 UDP `iperf` 业务流代理验证；P4 使用 `reg_path_mode=5` 按 IP-ID 中的 path hint 控制逐包路径，代理层用重复挂载提升轻微丢包下的成功率。
