# Wireshark 识别 INT 头部

本目录提供 `covert_int.lua`，用于让 Wireshark 识别项目中的紧凑 INT 头部。

## 支持的报文格式

- Inline INT：`IPv4(protocol=0xFD) | int_shim(4B) | probe_data[hop_count] | 原业务负载`
- INT 报告：`UDP/50100 | int_shim(4B) | probe_data[hop_count]`
- 保留以太类型入口：`EtherType=0x0812 | int_shim(4B) | probe_data[hop_count]`

Inline INT 会读取 `original_protocol` 字段，并把 INT 后面的剩余载荷继续交给 Wireshark 的 IPv4 协议表解析，因此原业务是 UDP/TCP/ICMP 时也能继续显示对应协议层。

## 字段布局

`int_shim_t` 固定 4 字节：

- byte0：`version(2 bit) + flags(2 bit) + hop_count(4 bit)`
- byte1：`original_protocol`
- byte2-3：`trace_id`

`probe_data_t` 每跳固定 48 字节：

- `swid`
- `port_ingress`
- `port_egress`
- `byte_ingress`
- `byte_egress`
- `count_ingress`
- `count_egress`
- `last_time_ingress`
- `last_time_egress`
- `current_time_ingress`
- `current_time_egress`
- `qdepth`

## Windows 安装

将 `covert_int.lua` 复制到 Wireshark 个人插件目录：

```powershell
$pluginDir = "$env:APPDATA\Wireshark\plugins"
New-Item -ItemType Directory -Force -Path $pluginDir
Copy-Item .\tools\wireshark\covert_int.lua $pluginDir\
```

然后重启 Wireshark。

## 常用过滤器

```text
int
ip.proto == 253
udp.port == 50100
int.shim.trace_id == 1
int.hop.swid == 2
```
