# 方案B策略测试汇总

## 方案说明

策略0/1现在都采用 2 字节同步标签：

- byte0：`frame_id(4bit) + strategy_id(2bit) + phase(2bit)`。
- byte1：`symbol_index(8bit)`。
- 两个字节发送前会做轻量异或混淆。

标签只做同步和分组，不承载隐蔽数据。隐蔽数据仍由业务流的包间隔关系承载。

## 关键结果

| 策略 | 0%丢包 | 1%丢包 |
|---|---|---|
| 策略0 | VM实测 209/209，完整解码 | VM实测 208/209，成功输出，1个未知bit |
| 策略1 | VM实测 157/157，完整解码 | VM实测 153/157，成功输出，4个未知符号 |

结论：方案B不负责恢复丢失的bit，但可以把丢包影响限制在局部符号，避免后续整体错位。

## 结果文件

- `int-test/results/scheme_b_mininet_results.json`
- `int-test/results/scheme_b_mininet_results.csv`
- `celue0/results_scheme_b/`
- `celue1/results_scheme_b/`
