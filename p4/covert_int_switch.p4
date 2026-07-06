/*
 * 面向低空网络多路径隐蔽传输的 BMv2/v1model P4 程序。
 *
 * 阶段1目标：
 * 1. h1 与 h2 的普通业务流正常通信，ping/iperf 不应因为 INT 中断。
 * 2. INT 由真实业务流触发，采样命中的业务包会在交换机间临时携带 INT 头。
 * 3. 终点交换机生成一份本地 UDP INT 报告，同时剥离 INT 并恢复原业务包。
 * 4. 交换机只负责转发、多路径选择和 INT 采样，隐蔽载荷由终端 Python 程序编解码。
 */

#include <core.p4>
#include <v1model.p4>

/*************************************************************************
 * 常量、头部与元数据定义
 *************************************************************************/

#define MAX_PORTS    10
#define MAX_INT_DATA 4

const bit<16> INT_ETHERTYPE = 0x0812;
const bit<2>  INT_VERSION = 1;
const bit<8>  INT_IPV4_PROTOCOL = 0xFD;
const bit<8>  UDP_PROTOCOL = 17;
const bit<16> INT_SHIM_BYTES = 4;
const bit<16> INT_PROBE_DATA_BYTES = 48;
const bit<16> INT_REPORT_UDP_SPORT = 50100;
const bit<16> INT_REPORT_UDP_DPORT = 50100;
const bit<16> INT_REPORT_UDP_BYTES = 8;
const bit<16> INT_REPORT_MCAST_GRP = 101;

const bit<3> PATH_MODE_DEFAULT = 0;
const bit<3> PATH_MODE_FIXED = 1;
const bit<3> PATH_MODE_ROUNDROBIN = 2;
const bit<3> PATH_MODE_REDUNDANT = 3;
const bit<3> PATH_MODE_WEIGHTED_RR = 4;
const bit<3> PATH_MODE_IPID_HINT = 5;

const bit<16> DEFAULT_REDUNDANCY_MCAST_GRP = 100;
const bit<9> HOST_PORT = 1;

const bit<48> S1_HOST_MAC  = 48w0x000000000101;
const bit<48> S1_PATH0_MAC = 48w0x000000000102;
const bit<48> S1_PATH1_MAC = 48w0x000000000103;
const bit<48> S1_PATH2_MAC = 48w0x000000000104;
const bit<48> S2_HOST_MAC  = 48w0x000000000201;
const bit<48> S2_PATH0_MAC = 48w0x000000000202;
const bit<48> S2_PATH1_MAC = 48w0x000000000203;
const bit<48> S2_PATH2_MAC = 48w0x000000000204;

/*
 * 部分旧版 v1model.p4 不暴露 PKT_INSTANCE_TYPE_NORMAL 名称。
 * BMv2 中普通原始包的 instance_type 为 0，克隆/组播副本通常不是 0。
 */
const bit<32> INSTANCE_TYPE_NORMAL = 0;

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header arp_t {
    bit<16> htype;
    bit<16> ptype;
    bit<8>  hlen;
    bit<8>  plen;
    bit<16> oper;
    bit<48> sha;
    bit<32> spa;
    bit<48> tha;
    bit<32> tpa;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

/*
 * INT shim 位于 IPv4 头之后、原 TCP/UDP/ICMP 头之前。
 * 该紧凑 shim 只保留恢复协议、跳数和探测序号，固定长度为 4 字节。
 */
header int_shim_t {
    bit<2>  version;
    bit<2>  flags;
    bit<4>  hop_count;
    bit<8>  original_protocol;
    bit<16> trace_id;
}

/*
 * 每跳遥测快照，长度固定为 48 字节。
 * 时间戳使用 BMv2 提供的微秒级全局时间。
 */
header probe_data_t {
    bit<8>  swid;
    bit<8>  port_ingress;
    bit<8>  port_egress;
    bit<8>  pad;
    bit<32> byte_ingress;
    bit<32> byte_egress;
    bit<32> count_ingress;
    bit<32> count_egress;
    bit<48> last_time_ingress;
    bit<48> last_time_egress;
    bit<48> current_time_ingress;
    bit<48> current_time_egress;
    bit<32> qdepth;
}

struct int_metadata_t {
    bit<1> is_int;
    bit<1> is_terminal;
    bit<8> swid;
    bit<8> path_id;
}

struct headers {
    ethernet_t ethernet;
    arp_t arp;
    ipv4_t ipv4;
    udp_t udp;
    int_shim_t int_shim;
    probe_data_t[MAX_INT_DATA] probe_data;
}

struct metadata {
    int_metadata_t int_meta;
    @field_list(1)
    bit<8> probe_data_cnt;
}

/*************************************************************************
 * 寄存器定义
 *************************************************************************/

/* 每个端口维护累计字节数、包数和上一次 INT 采样时间。 */
register<bit<32>>(MAX_PORTS) reg_byte_ingress;
register<bit<32>>(MAX_PORTS) reg_byte_egress;
register<bit<32>>(MAX_PORTS) reg_count_ingress;
register<bit<32>>(MAX_PORTS) reg_count_egress;
register<bit<48>>(MAX_PORTS) reg_last_time_ingress;
register<bit<48>>(MAX_PORTS) reg_last_time_egress;

/* INT 采样控制。 */
register<bit<32>>(1) reg_int_interval_us;
register<bit<48>>(1) reg_next_sample_time;
register<bit<8>>(1)  reg_int_enabled;
register<bit<8>>(1)  reg_switch_id;
register<bit<8>>(1)  reg_int_terminal_swid;
register<bit<32>>(1) reg_int_dst_filter;
register<bit<8>>(1)  reg_int_proto_filter;
register<bit<8>>(1)  reg_int_probe_path;
register<bit<16>>(3) reg_int_seq_path;
register<bit<8>>(1)  reg_int_probe_mode;
register<bit<8>>(1)  reg_int_fixed_probe_path;

/* 多路径调度控制。 */
register<bit<3>>(1)  reg_path_mode;
register<bit<8>>(1)  reg_fixed_path;
register<bit<32>>(1) reg_rr_burst_size;
register<bit<32>>(1) reg_rr_counter;
register<bit<8>>(1)  reg_rr_current_path;
register<bit<32>>(1) reg_wrr_weight0;
register<bit<32>>(1) reg_wrr_weight1;
register<bit<32>>(1) reg_wrr_weight2;
register<bit<32>>(1) reg_wrr_counter;
register<bit<16>>(1) reg_redundancy_mcast_grp;

/*************************************************************************
 * Parser
 *************************************************************************/

parser CovertIntParser(
    packet_in packet,
    out headers hdr,
    inout metadata meta,
    inout standard_metadata_t std_meta)
{
    state start {
        meta.int_meta.is_int = 0;
        meta.int_meta.is_terminal = 0;
        meta.int_meta.swid = 0;
        meta.int_meta.path_id = 0;
        meta.probe_data_cnt = 0;
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0806: parse_arp;
            0x0800: parse_ipv4;
            INT_ETHERTYPE: parse_int_shim;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            INT_IPV4_PROTOCOL: parse_int_shim;
            default: accept;
        }
    }

    state parse_int_shim {
        packet.extract(hdr.int_shim);
        meta.int_meta.is_int = 1;
        transition parse_probe_data;
    }

    state parse_probe_data {
        transition select(
            ((bit<4>)meta.probe_data_cnt < hdr.int_shim.hop_count) &&
            (meta.probe_data_cnt < MAX_INT_DATA)) {
            true: parse_probe_data_one;
            false: accept;
        }
    }

    state parse_probe_data_one {
        packet.extract(hdr.probe_data.next);
        meta.probe_data_cnt = meta.probe_data_cnt + 1;
        transition parse_probe_data;
    }
}

/*************************************************************************
 * IPv4 校验和
 *************************************************************************/

control CovertIntVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        verify_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

control CovertIntComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
 * Ingress：累计入端口状态、按时间采样插入 INT、选择多路径
 *************************************************************************/

control CovertIntIngress(
    inout headers hdr,
    inout metadata meta,
    inout standard_metadata_t std_meta)
{
    action ipv4_forward(bit<48> dst_mac, bit<48> src_mac, bit<9> port) {
        hdr.ethernet.dstAddr = dst_mac;
        hdr.ethernet.srcAddr = src_mac;
        std_meta.egress_spec = port;
        if (hdr.ipv4.ttl > 0) {
            hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        } else {
            mark_to_drop(std_meta);
        }
    }

    action drop() {
        mark_to_drop(std_meta);
    }

    action arp_reply(bit<48> my_mac) {
        bit<48> requester_mac = hdr.arp.sha;
        bit<32> requester_ip = hdr.arp.spa;
        bit<32> target_ip = hdr.arp.tpa;

        hdr.ethernet.dstAddr = requester_mac;
        hdr.ethernet.srcAddr = my_mac;
        hdr.arp.oper = 2;
        hdr.arp.tha = requester_mac;
        hdr.arp.tpa = requester_ip;
        hdr.arp.sha = my_mac;
        hdr.arp.spa = target_ip;
        std_meta.egress_spec = std_meta.ingress_port;
    }

    action route_by_path(bit<8> path_id, bit<9> port_0, bit<9> port_1, bit<9> port_2) {
        meta.int_meta.path_id = path_id;
        if (path_id == 0) {
            std_meta.egress_spec = port_0;
        } else if (path_id == 1) {
            std_meta.egress_spec = port_1;
        } else {
            std_meta.egress_spec = port_2;
        }
    }

    table ipv4_lpm {
        key = { hdr.ipv4.dstAddr: lpm; }
        actions = { ipv4_forward; drop; NoAction; }
        size = 64;
        default_action = drop();
    }

    table arp_request_table {
        key = {
            hdr.arp.oper: exact;
            hdr.arp.tpa: exact;
        }
        actions = { arp_reply; drop; NoAction; }
        size = 8;
        default_action = drop();
    }

    table path_to_port {
        key = { meta.int_meta.path_id: exact; }
        actions = { route_by_path; NoAction; }
        size = 8;
        default_action = NoAction();
    }

    apply {
        bit<8> int_enabled;
        bit<8> swid;
        bit<8> terminal_swid;
        reg_int_enabled.read(int_enabled, 0);
        reg_switch_id.read(swid, 0);
        reg_int_terminal_swid.read(terminal_swid, 0);
        meta.int_meta.swid = swid;
        meta.int_meta.path_id = 0;

        bit<32> port_idx = (bit<32>)std_meta.ingress_port;

        bit<32> byte_in;
        reg_byte_ingress.read(byte_in, port_idx);
        byte_in = byte_in + std_meta.packet_length;
        reg_byte_ingress.write(port_idx, byte_in);

        bit<32> cnt_in;
        reg_count_ingress.read(cnt_in, port_idx);
        cnt_in = cnt_in + 1;
        reg_count_ingress.write(port_idx, cnt_in);

        bit<48> now_ts = (bit<48>)std_meta.ingress_global_timestamp;
        bit<48> next_sample;
        bit<32> interval;
        bit<32> int_dst_filter;
        bit<8> int_proto_filter;
        reg_next_sample_time.read(next_sample, 0);
        reg_int_interval_us.read(interval, 0);
        reg_int_dst_filter.read(int_dst_filter, 0);
        reg_int_proto_filter.read(int_proto_filter, 0);

        bool match_int_direction =
            hdr.ipv4.isValid() &&
            ((int_dst_filter == 0) || (hdr.ipv4.dstAddr == int_dst_filter));
        bool match_int_protocol =
            hdr.ipv4.isValid() &&
            ((int_proto_filter == 0) || (hdr.ipv4.protocol == int_proto_filter));
        bool is_unfragmented =
            hdr.ipv4.isValid() &&
            (hdr.ipv4.fragOffset == 0) &&
            (hdr.ipv4.flags[0:0] == 0);

        bool sample_time_ready =
            (interval == 0) ||
            (now_ts >= next_sample);

        bool should_sample =
            (int_enabled == 1) &&
            match_int_direction &&
            match_int_protocol &&
            is_unfragmented &&
            sample_time_ready;

        if (hdr.int_shim.isValid()) {
            bit<8> hop_idx = meta.probe_data_cnt;
            bit<48> last_t_in;
            reg_last_time_ingress.read(last_t_in, port_idx);

            if (hop_idx < (bit<8>)MAX_INT_DATA) {
                if (hop_idx == 0) {
                    hdr.probe_data[0].setValid();
                    hdr.probe_data[0].swid = swid;
                    hdr.probe_data[0].port_ingress = (bit<8>)std_meta.ingress_port;
                    hdr.probe_data[0].port_egress = 0;
                    hdr.probe_data[0].pad = 0;
                    reg_byte_ingress.read(hdr.probe_data[0].byte_ingress, port_idx);
                    reg_count_ingress.read(hdr.probe_data[0].count_ingress, port_idx);
                    hdr.probe_data[0].last_time_ingress = last_t_in;
                    hdr.probe_data[0].current_time_ingress = now_ts;
                } else if (hop_idx == 1) {
                    hdr.probe_data[1].setValid();
                    hdr.probe_data[1].swid = swid;
                    hdr.probe_data[1].port_ingress = (bit<8>)std_meta.ingress_port;
                    hdr.probe_data[1].port_egress = 0;
                    hdr.probe_data[1].pad = 0;
                    reg_byte_ingress.read(hdr.probe_data[1].byte_ingress, port_idx);
                    reg_count_ingress.read(hdr.probe_data[1].count_ingress, port_idx);
                    hdr.probe_data[1].last_time_ingress = last_t_in;
                    hdr.probe_data[1].current_time_ingress = now_ts;
                } else if (hop_idx == 2) {
                    hdr.probe_data[2].setValid();
                    hdr.probe_data[2].swid = swid;
                    hdr.probe_data[2].port_ingress = (bit<8>)std_meta.ingress_port;
                    hdr.probe_data[2].port_egress = 0;
                    hdr.probe_data[2].pad = 0;
                    reg_byte_ingress.read(hdr.probe_data[2].byte_ingress, port_idx);
                    reg_count_ingress.read(hdr.probe_data[2].count_ingress, port_idx);
                    hdr.probe_data[2].last_time_ingress = last_t_in;
                    hdr.probe_data[2].current_time_ingress = now_ts;
                } else {
                    hdr.probe_data[3].setValid();
                    hdr.probe_data[3].swid = swid;
                    hdr.probe_data[3].port_ingress = (bit<8>)std_meta.ingress_port;
                    hdr.probe_data[3].port_egress = 0;
                    hdr.probe_data[3].pad = 0;
                    reg_byte_ingress.read(hdr.probe_data[3].byte_ingress, port_idx);
                    reg_count_ingress.read(hdr.probe_data[3].count_ingress, port_idx);
                    hdr.probe_data[3].last_time_ingress = last_t_in;
                    hdr.probe_data[3].current_time_ingress = now_ts;
                }

                reg_last_time_ingress.write(port_idx, now_ts);
                meta.probe_data_cnt = meta.probe_data_cnt + 1;
                hdr.int_shim.hop_count = (bit<4>)meta.probe_data_cnt;
                if (hdr.ipv4.isValid()) {
                    hdr.ipv4.totalLen = hdr.ipv4.totalLen + INT_PROBE_DATA_BYTES;
                }
            }
        }

        /*
         * INT 终点交换机用本地组播复制两份：
         * rid=0 的副本剥离 INT 后作为原业务包交给终端；
         * rid=1 的副本转换为 UDP/50100 INT 报告交给本地解析程序。
         */
        if (meta.int_meta.is_int == 1 &&
            terminal_swid != 0 &&
            swid == terminal_swid) {
            meta.int_meta.is_terminal = 1;
            std_meta.mcast_grp = INT_REPORT_MCAST_GRP;
        }

        if (hdr.arp.isValid()) {
            arp_request_table.apply();
        }

        if (hdr.ipv4.isValid()) {
            bit<3> path_mode;
            reg_path_mode.read(path_mode, 0);
            ipv4_lpm.apply();

            /*
             * 只有本来要发往交换机间链路的包才允许覆盖出端口。
             * 目的地已经是本地终端时，必须保持 HOST_PORT。
             */
            if (std_meta.egress_spec != HOST_PORT) {
                if (path_mode == PATH_MODE_FIXED) {
                    bit<8> fixed_path;
                    reg_fixed_path.read(fixed_path, 0);
                    if (fixed_path > 2) {
                        meta.int_meta.path_id = 2;
                    } else {
                        meta.int_meta.path_id = fixed_path;
                    }
                    path_to_port.apply();
                } else if (path_mode == PATH_MODE_ROUNDROBIN) {
                    bit<32> burst_size;
                    bit<32> rr_counter;
                    bit<8> rr_path;
                    reg_rr_burst_size.read(burst_size, 0);
                    reg_rr_counter.read(rr_counter, 0);
                    reg_rr_current_path.read(rr_path, 0);

                    if (burst_size == 0) {
                        burst_size = 1;
                    }
                    if (rr_path > 2) {
                        rr_path = 0;
                    }

                    meta.int_meta.path_id = rr_path;
                    rr_counter = rr_counter + 1;
                    if (rr_counter >= burst_size) {
                        rr_counter = 0;
                        if (rr_path == 0) {
                            rr_path = 1;
                        } else if (rr_path == 1) {
                            rr_path = 2;
                        } else {
                            rr_path = 0;
                        }
                        reg_rr_current_path.write(0, rr_path);
                    }
                    reg_rr_counter.write(0, rr_counter);
                    path_to_port.apply();
                } else if (path_mode == PATH_MODE_WEIGHTED_RR) {
                    bit<32> w0;
                    bit<32> w1;
                    bit<32> w2;
                    bit<32> total_w;
                    bit<32> pos;
                    bit<32> wrr_counter;
                    reg_wrr_weight0.read(w0, 0);
                    reg_wrr_weight1.read(w1, 0);
                    reg_wrr_weight2.read(w2, 0);
                    reg_wrr_counter.read(wrr_counter, 0);
                    total_w = w0 + w1 + w2;
                    if (total_w == 0) {
                        meta.int_meta.path_id = 0;
                    } else {
                        pos = wrr_counter;
                        if (pos < w0) {
                            meta.int_meta.path_id = 0;
                        } else if (pos < (w0 + w1)) {
                            meta.int_meta.path_id = 1;
                        } else {
                            meta.int_meta.path_id = 2;
                        }
                        wrr_counter = wrr_counter + 1;
                        if (wrr_counter >= total_w) {
                            wrr_counter = 0;
                        }
                        reg_wrr_counter.write(0, wrr_counter);
                    }
                    path_to_port.apply();
                } else if (path_mode == PATH_MODE_IPID_HINT) {
                    /*
                     * 策略5把期望路径写在 IPv4 Identification 中：
                     * valid=1、strategy_id=5 时高4位为 0xD，bit[11:10] 为 path_id。
                     * 交换机只读取路径提示，不解析真实隐蔽数据。
                     */
                    if (hdr.ipv4.identification[15:12] == 4w0xD) {
                        bit<2> hinted_path = hdr.ipv4.identification[11:10];
                        if (hinted_path == 0) {
                            meta.int_meta.path_id = 0;
                        } else if (hinted_path == 1) {
                            meta.int_meta.path_id = 1;
                        } else {
                            meta.int_meta.path_id = 2;
                        }
                    } else {
                        meta.int_meta.path_id = 0;
                    }
                    path_to_port.apply();
                } else if (path_mode == PATH_MODE_REDUNDANT && !hdr.int_shim.isValid()) {
                    bit<16> mcast_grp;
                    reg_redundancy_mcast_grp.read(mcast_grp, 0);
                    if (mcast_grp == 0) {
                        mcast_grp = DEFAULT_REDUNDANCY_MCAST_GRP;
                    }
                    std_meta.mcast_grp = mcast_grp;
                }
            }

            /*
             * 真实业务包 inline INT。
             * 采样命中时，当前业务包本身在交换机间携带 INT 头；终点交换机会生成
             * 本地 UDP 报告，并在交给终端前剥掉 INT、恢复原 IPv4 协议和长度。
             */
            if (should_sample &&
                !hdr.int_shim.isValid() &&
                std_meta.egress_spec != HOST_PORT &&
                path_mode != PATH_MODE_REDUNDANT) {
                bit<8> sampled_path = meta.int_meta.path_id;
                if (std_meta.egress_spec == 2) {
                    sampled_path = 0;
                } else if (std_meta.egress_spec == 3) {
                    sampled_path = 1;
                } else if (std_meta.egress_spec == 4) {
                    sampled_path = 2;
                } else if (sampled_path > 2) {
                    sampled_path = 2;
                }
                meta.int_meta.path_id = sampled_path;

                bit<32> seq_idx = (bit<32>)sampled_path;
                bit<16> seq_id;
                reg_int_seq_path.read(seq_id, seq_idx);
                seq_id = seq_id + 1;
                reg_int_seq_path.write(seq_idx, seq_id);

                hdr.int_shim.setValid();
                hdr.int_shim.version = INT_VERSION;
                hdr.int_shim.flags = 0;
                hdr.int_shim.hop_count = 1;
                hdr.int_shim.original_protocol = hdr.ipv4.protocol;
                hdr.int_shim.trace_id = seq_id;

                hdr.ipv4.protocol = INT_IPV4_PROTOCOL;
                hdr.ipv4.totalLen =
                    hdr.ipv4.totalLen + INT_SHIM_BYTES + INT_PROBE_DATA_BYTES;

                bit<48> sample_last_t_in;
                reg_last_time_ingress.read(sample_last_t_in, port_idx);
                hdr.probe_data[0].setValid();
                hdr.probe_data[0].swid = swid;
                hdr.probe_data[0].port_ingress = (bit<8>)std_meta.ingress_port;
                hdr.probe_data[0].port_egress = 0;
                hdr.probe_data[0].pad = 0;
                reg_byte_ingress.read(hdr.probe_data[0].byte_ingress, port_idx);
                hdr.probe_data[0].byte_egress = 0;
                reg_count_ingress.read(hdr.probe_data[0].count_ingress, port_idx);
                hdr.probe_data[0].count_egress = 0;
                hdr.probe_data[0].last_time_ingress = sample_last_t_in;
                hdr.probe_data[0].last_time_egress = 0;
                hdr.probe_data[0].current_time_ingress = now_ts;
                hdr.probe_data[0].current_time_egress = 0;
                hdr.probe_data[0].qdepth = 0;

                reg_last_time_ingress.write(port_idx, now_ts);
                meta.probe_data_cnt = 1;
                meta.int_meta.is_int = 1;

                if (interval != 0) {
                    reg_next_sample_time.write(0, now_ts + (bit<48>)interval);
                }
            }
        }
    }
}

/*************************************************************************
 * Egress：累计出端口状态、补齐 egress 快照、恢复业务包
 *************************************************************************/

control CovertIntEgress(
    inout headers hdr,
    inout metadata meta,
    inout standard_metadata_t std_meta)
{
    apply {
        bit<32> port_idx = (bit<32>)std_meta.egress_port;
        bit<32> pkt_len_out = std_meta.packet_length;
        if (hdr.ipv4.isValid()) {
            pkt_len_out = (bit<32>)hdr.ipv4.totalLen + (bit<32>)14;
        }

        bit<32> byte_out;
        reg_byte_egress.read(byte_out, port_idx);
        byte_out = byte_out + pkt_len_out;
        reg_byte_egress.write(port_idx, byte_out);

        bit<32> cnt_out;
        reg_count_egress.read(cnt_out, port_idx);
        cnt_out = cnt_out + 1;
        reg_count_egress.write(port_idx, cnt_out);

        if (hdr.int_shim.isValid() && meta.probe_data_cnt > 0) {
            bit<8> hop_idx = meta.probe_data_cnt - 1;
            bit<48> last_t_out;
            reg_last_time_egress.read(last_t_out, port_idx);
            bit<48> now_egress = (bit<48>)std_meta.egress_global_timestamp;

            if (hop_idx == 0) {
                hdr.probe_data[0].port_egress = (bit<8>)std_meta.egress_port;
                reg_byte_egress.read(hdr.probe_data[0].byte_egress, port_idx);
                reg_count_egress.read(hdr.probe_data[0].count_egress, port_idx);
                hdr.probe_data[0].last_time_egress = last_t_out;
                hdr.probe_data[0].current_time_egress = now_egress;
                hdr.probe_data[0].qdepth = (bit<32>)std_meta.deq_qdepth;
            } else if (hop_idx == 1) {
                hdr.probe_data[1].port_egress = (bit<8>)std_meta.egress_port;
                reg_byte_egress.read(hdr.probe_data[1].byte_egress, port_idx);
                reg_count_egress.read(hdr.probe_data[1].count_egress, port_idx);
                hdr.probe_data[1].last_time_egress = last_t_out;
                hdr.probe_data[1].current_time_egress = now_egress;
                hdr.probe_data[1].qdepth = (bit<32>)std_meta.deq_qdepth;
            } else if (hop_idx == 2) {
                hdr.probe_data[2].port_egress = (bit<8>)std_meta.egress_port;
                reg_byte_egress.read(hdr.probe_data[2].byte_egress, port_idx);
                reg_count_egress.read(hdr.probe_data[2].count_egress, port_idx);
                hdr.probe_data[2].last_time_egress = last_t_out;
                hdr.probe_data[2].current_time_egress = now_egress;
                hdr.probe_data[2].qdepth = (bit<32>)std_meta.deq_qdepth;
            } else {
                hdr.probe_data[3].port_egress = (bit<8>)std_meta.egress_port;
                reg_byte_egress.read(hdr.probe_data[3].byte_egress, port_idx);
                reg_count_egress.read(hdr.probe_data[3].count_egress, port_idx);
                hdr.probe_data[3].last_time_egress = last_t_out;
                hdr.probe_data[3].current_time_egress = now_egress;
                hdr.probe_data[3].qdepth = (bit<32>)std_meta.deq_qdepth;
            }

            reg_last_time_egress.write(port_idx, now_egress);
        }

        /*
         * 标准三层转发语义：多路径模式可能在 ingress 中覆盖出端口，
         * 因此在 egress 按实际出端口重写交换机间链路的二层 MAC。
         * 主机端口的 MAC 由 ipv4_lpm 的 ipv4_forward action 写入。
         */
        if (hdr.ipv4.isValid() && std_meta.egress_port != HOST_PORT) {
            if (meta.int_meta.swid == 1) {
                if (std_meta.egress_port == 2) {
                    hdr.ethernet.srcAddr = S1_PATH0_MAC;
                    hdr.ethernet.dstAddr = S2_PATH0_MAC;
                } else if (std_meta.egress_port == 3) {
                    hdr.ethernet.srcAddr = S1_PATH1_MAC;
                    hdr.ethernet.dstAddr = S2_PATH1_MAC;
                } else if (std_meta.egress_port == 4) {
                    hdr.ethernet.srcAddr = S1_PATH2_MAC;
                    hdr.ethernet.dstAddr = S2_PATH2_MAC;
                }
            } else if (meta.int_meta.swid == 2) {
                if (std_meta.egress_port == 2) {
                    hdr.ethernet.srcAddr = S2_PATH0_MAC;
                    hdr.ethernet.dstAddr = S1_PATH0_MAC;
                } else if (std_meta.egress_port == 3) {
                    hdr.ethernet.srcAddr = S2_PATH1_MAC;
                    hdr.ethernet.dstAddr = S1_PATH1_MAC;
                } else if (std_meta.egress_port == 4) {
                    hdr.ethernet.srcAddr = S2_PATH2_MAC;
                    hdr.ethernet.dstAddr = S1_PATH2_MAC;
                }
            }
        }

        if (((meta.int_meta.is_terminal == 1 &&
              std_meta.egress_rid == 1) ||
              (meta.int_meta.is_terminal == 1 &&
               std_meta.instance_type == INSTANCE_TYPE_NORMAL &&
               hdr.int_shim.flags == 3)) &&
            hdr.int_shim.isValid()) {
            bit<16> report_payload_len = INT_SHIM_BYTES +
                ((bit<16>)hdr.int_shim.hop_count * INT_PROBE_DATA_BYTES);
            bit<16> udp_len = INT_REPORT_UDP_BYTES + report_payload_len;

            hdr.udp.setValid();
            hdr.udp.srcPort = INT_REPORT_UDP_SPORT;
            hdr.udp.dstPort = INT_REPORT_UDP_DPORT;
            hdr.udp.length = udp_len;
            hdr.udp.checksum = 0;

            if (hdr.ipv4.isValid()) {
                hdr.ipv4.protocol = UDP_PROTOCOL;
                hdr.ipv4.totalLen = 20 + udp_len;
                truncate((bit<32>)(14 + 20) + (bit<32>)udp_len);
            }
        }

        /*
         * 只恢复原始业务包。rid=1 的本地报告副本在上面的分支中已经转换为 UDP 报告。
         */
        if (meta.int_meta.is_terminal == 1 &&
            std_meta.egress_rid != 1 &&
            hdr.int_shim.isValid() &&
            hdr.int_shim.flags != 3) {
            if (hdr.ipv4.isValid()) {
                bit<16> inline_int_len = INT_SHIM_BYTES +
                    ((bit<16>)hdr.int_shim.hop_count * INT_PROBE_DATA_BYTES);
                hdr.ipv4.protocol = hdr.int_shim.original_protocol;
                hdr.ipv4.totalLen = hdr.ipv4.totalLen - inline_int_len;
            }
            hdr.int_shim.setInvalid();
            hdr.probe_data[0].setInvalid();
            hdr.probe_data[1].setInvalid();
            hdr.probe_data[2].setInvalid();
            hdr.probe_data[3].setInvalid();
            meta.int_meta.is_int = 0;
        }
    }
}

/*************************************************************************
 * Deparser
 *************************************************************************/

control CovertIntDeparser(packet_out packet, in headers hdr)
{
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.int_shim);
        packet.emit(hdr.probe_data);
    }
}

/*************************************************************************
 * v1model 主流水线
 *************************************************************************/

V1Switch(
    CovertIntParser(),
    CovertIntVerifyChecksum(),
    CovertIntIngress(),
    CovertIntEgress(),
    CovertIntComputeChecksum(),
    CovertIntDeparser()
) main;
