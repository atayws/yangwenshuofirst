-- Wireshark Lua dissector for the compact INT header.
--
-- Supported packet formats:
--   1. Inline INT:
--      Ethernet | IPv4(protocol=0xFD) | int_shim(4B) | probe_data[hop_count] | original L4 payload
--   2. INT report:
--      Ethernet | IPv4 | UDP(src/dst port 50100) | int_shim(4B) | probe_data[hop_count]
--   3. Reserved Ethernet entry:
--      Ethernet(type=0x0812) | int_shim(4B) | probe_data[hop_count]
--
-- Current P4 layout:
--   int_shim_t:
--     byte0: version(2b), flags(2b), hop_count(4b)
--     byte1: original_protocol(8b)
--     byte2-3: trace_id(16b)
--   probe_data_t: 48 bytes per hop.

local int_proto = Proto("int", "INT")

local f_shim0 = ProtoField.uint8("int.shim.byte0", "Shim Byte0", base.HEX)
local f_version = ProtoField.uint8("int.shim.version", "Version", base.DEC, nil, 0xC0)
local f_flags = ProtoField.uint8("int.shim.flags", "Flags", base.DEC, nil, 0x30)
local f_hop_count = ProtoField.uint8("int.shim.hop_count", "Hop Count", base.DEC, nil, 0x0F)
local f_original_protocol = ProtoField.uint8("int.shim.original_protocol", "Original IPv4 Protocol", base.DEC)
local f_trace_id = ProtoField.uint16("int.shim.trace_id", "Trace ID", base.DEC)

local f_hop_index = ProtoField.uint8("int.hop.index", "Hop Index", base.DEC)
local f_swid = ProtoField.uint8("int.hop.swid", "Switch ID", base.DEC)
local f_port_ingress = ProtoField.uint8("int.hop.port_ingress", "Ingress Port", base.DEC)
local f_port_egress = ProtoField.uint8("int.hop.port_egress", "Egress Port", base.DEC)
local f_pad = ProtoField.uint8("int.hop.pad", "Pad", base.HEX)
local f_byte_ingress = ProtoField.uint32("int.hop.byte_ingress", "Ingress Bytes Snapshot", base.DEC)
local f_byte_egress = ProtoField.uint32("int.hop.byte_egress", "Egress Bytes Snapshot", base.DEC)
local f_count_ingress = ProtoField.uint32("int.hop.count_ingress", "Ingress Packet Count Snapshot", base.DEC)
local f_count_egress = ProtoField.uint32("int.hop.count_egress", "Egress Packet Count Snapshot", base.DEC)
local f_last_time_ingress = ProtoField.uint64("int.hop.last_time_ingress", "Last Ingress Time(us)", base.DEC)
local f_last_time_egress = ProtoField.uint64("int.hop.last_time_egress", "Last Egress Time(us)", base.DEC)
local f_current_time_ingress = ProtoField.uint64("int.hop.current_time_ingress", "Current Ingress Time(us)", base.DEC)
local f_current_time_egress = ProtoField.uint64("int.hop.current_time_egress", "Current Egress Time(us)", base.DEC)
local f_qdepth = ProtoField.uint32("int.hop.qdepth", "Queue Depth", base.DEC)
local f_remaining_payload = ProtoField.bytes("int.remaining_payload", "Original Payload / Remaining Bytes")

int_proto.fields = {
    f_shim0,
    f_version,
    f_flags,
    f_hop_count,
    f_original_protocol,
    f_trace_id,
    f_hop_index,
    f_swid,
    f_port_ingress,
    f_port_egress,
    f_pad,
    f_byte_ingress,
    f_byte_egress,
    f_count_ingress,
    f_count_egress,
    f_last_time_ingress,
    f_last_time_egress,
    f_current_time_ingress,
    f_current_time_egress,
    f_qdepth,
    f_remaining_payload,
}

local SHIM_LEN = 4
local PROBE_LEN = 48
local MAX_HOPS = 4
local INT_IPV4_PROTOCOL = 0xFD
local INT_REPORT_UDP_PORT = 50100
local INT_ETHERTYPE = 0x0812
local ip_proto_table = DissectorTable.get("ip.proto")

local function read_u48(buffer, offset)
    local value = UInt64(0)
    for i = 0, 5 do
        value = value * UInt64(256) + UInt64(buffer(offset + i, 1):uint())
    end
    return value
end

local function add_u48(tree, field, buffer, offset)
    tree:add(field, buffer(offset, 6), read_u48(buffer, offset))
end

local function dissect_probe(buffer, offset, tree, index)
    local hop_tree = tree:add(int_proto, buffer(offset, PROBE_LEN), string.format("Probe Data Hop %d", index))
    hop_tree:add(f_hop_index, index)
    hop_tree:add(f_swid, buffer(offset, 1))
    hop_tree:add(f_port_ingress, buffer(offset + 1, 1))
    hop_tree:add(f_port_egress, buffer(offset + 2, 1))
    hop_tree:add(f_pad, buffer(offset + 3, 1))
    hop_tree:add(f_byte_ingress, buffer(offset + 4, 4))
    hop_tree:add(f_byte_egress, buffer(offset + 8, 4))
    hop_tree:add(f_count_ingress, buffer(offset + 12, 4))
    hop_tree:add(f_count_egress, buffer(offset + 16, 4))
    add_u48(hop_tree, f_last_time_ingress, buffer, offset + 20)
    add_u48(hop_tree, f_last_time_egress, buffer, offset + 26)
    add_u48(hop_tree, f_current_time_ingress, buffer, offset + 32)
    add_u48(hop_tree, f_current_time_egress, buffer, offset + 38)
    hop_tree:add(f_qdepth, buffer(offset + 44, 4))
end

function int_proto.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length < SHIM_LEN then
        return 0
    end

    pinfo.cols.protocol = "INT"

    local shim0 = buffer(0, 1):uint()
    local version = bit.rshift(bit.band(shim0, 0xC0), 6)
    local flags = bit.rshift(bit.band(shim0, 0x30), 4)
    local hop_count = bit.band(shim0, 0x0F)
    local original_protocol = buffer(1, 1):uint()
    local trace_id = buffer(2, 2):uint()

    local subtree = tree:add(int_proto, buffer(), "INT")
    local shim_tree = subtree:add(int_proto, buffer(0, SHIM_LEN), "Compact INT Shim")
    shim_tree:add(f_shim0, buffer(0, 1))
    shim_tree:add(f_version, buffer(0, 1))
    shim_tree:add(f_flags, buffer(0, 1))
    shim_tree:add(f_hop_count, buffer(0, 1))
    shim_tree:add(f_original_protocol, buffer(1, 1))
    shim_tree:add(f_trace_id, buffer(2, 2))

    local valid_hops = math.min(hop_count, MAX_HOPS)
    local offset = SHIM_LEN
    local parsed_hops = 0
    for i = 0, valid_hops - 1 do
        if offset + PROBE_LEN > length then
            subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Truncated probe_data_t")
            break
        end
        dissect_probe(buffer, offset, subtree, i)
        offset = offset + PROBE_LEN
        parsed_hops = parsed_hops + 1
    end

    if offset < length then
        local payload_range = buffer(offset, length - offset)
        subtree:add(f_remaining_payload, payload_range)
        local next_dissector = ip_proto_table:get_dissector(original_protocol)
        if next_dissector ~= nil then
            next_dissector:call(payload_range:tvb(), pinfo, tree)
        end
    end

    local info = string.format(
        "INT ver=%d flags=%d hops=%d parsed=%d original_proto=%d trace_id=%d",
        version,
        flags,
        hop_count,
        parsed_hops,
        original_protocol,
        trace_id
    )
    pinfo.cols.info:append(" [" .. info .. "]")
    return length
end

DissectorTable.get("ip.proto"):add(INT_IPV4_PROTOCOL, int_proto)
DissectorTable.get("udp.port"):add(INT_REPORT_UDP_PORT, int_proto)
DissectorTable.get("ethertype"):add(INT_ETHERTYPE, int_proto)
