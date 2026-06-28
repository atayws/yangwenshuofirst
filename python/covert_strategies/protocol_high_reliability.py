"""
策略2：可靠 IP-ID 存储信道。

该策略把 IPv4 Identification 字段作为低开销承载位置。字段布局保持 16 bit：
bit15       covert_flag = 1
bits14-12   strategy_id = 2
bits11-8    seq_mod，块内片段序号 0~15
bits7-0     encrypted_value

encrypted_value 解密后再拆成两部分：
高4 bit      block_mod，块号模16，用于乱序/丢包后的重新分组
低4 bit      data_nibble，真实数据半字节或冗余半字节

每块包含 12 个数据半字节、3 个 XOR 冗余半字节和 1 个认证半字节，并默认重复发送每个片段 3 次。这样牺牲一部分容量，换来随机丢包下的可恢复性。
"""

import hashlib
from dataclasses import dataclass
from typing import Dict, List, Optional

from .base import CovertStrategy, PacketSpec, StrategyMetrics, PathState, StrategyID
from .strategy_registry import register_strategy


STRATEGY2_VALID_MASK = 0x8000
STRATEGY2_STRATEGY_MASK = 0x7000
STRATEGY2_SEQ_MASK = 0x0F00
STRATEGY2_VALUE_MASK = 0x00FF
STRATEGY2_STRATEGY_SHIFT = 12
STRATEGY2_SEQ_SHIFT = 8


@dataclass
class Strategy2Candidate:
    """一个通过 IP-ID 头部初筛的策略2候选片段。"""

    block_id: int
    seq_mod: int
    plain_nibble: int
    ip_id: int
    block_mod: int


@register_strategy
class ProtocolHighReliabilityStrategy(CovertStrategy):
    """策略2：带块序号、块认证和 XOR 冗余的可靠 IP-ID 存储信道。"""

    strategy_id = StrategyID.PROTOCOL_HIGH_RELIABILITY
    name = "protocol_high_reliability"
    description = (
        "IPv4 ID 字段可靠存储信道：flag + strategy + seq_mod + encrypted_value，"
        "解密后得到 block_mod + data_nibble，每块 12 个数据半字节、3 个 XOR 冗余和 1 个认证。"
    )

    DATA_UNITS = 12
    PARITY_UNITS = 3
    AUTH_SEQ = 15
    BLOCK_UNITS = 16
    FRAME_MAGIC = b"P2"
    MAX_BLOCKS_WITHOUT_FRAGMENT_ID = 16

    def __init__(self, config: Optional[dict] = None):
        super().__init__(config)
        key = self._config.get("secret_key", b"low-altitude-covert-ipid-v3")
        if isinstance(key, str):
            key = key.encode("utf-8")
        self._secret_key = key
        self._repeat_count = max(1, int(self._config.get("repeat_count", 3)))
        self.last_decode_info: Dict[str, object] = {}

    def encode(
        self, data: bytes, path_id: int, seq_num: int = 0
    ) -> List[PacketSpec]:
        """把隐蔽数据编码成一组带 IP-ID 字段的承载包描述。"""
        framed = self.FRAME_MAGIC + len(data).to_bytes(4, "big") + data
        blocks = self._split_blocks(self._bytes_to_nibbles(framed))
        packets: List[PacketSpec] = []
        total_fragments = len(blocks) * self.BLOCK_UNITS * self._repeat_count

        for block_id, data_units in enumerate(blocks):
            parity_units = self._build_parity(data_units)
            auth_value = self._auth_nibble(block_id, data_units + parity_units)
            plain_units = data_units + parity_units + [auth_value]
            block_mod = block_id & 0x0F

            for seq_mod, plain_nibble in enumerate(plain_units):
                plain_value = ((block_mod & 0x0F) << 4) | (plain_nibble & 0x0F)
                cipher_value = plain_value ^ self._keystream_byte(block_mod, seq_mod)
                ip_id = self._pack_ip_id(seq_mod, cipher_value)
                fragment_id = block_id * self.BLOCK_UNITS + seq_mod
                for repeat_index in range(self._repeat_count):
                    packets.append(
                        PacketSpec(
                            payload=b"\x00",
                            sequence_num=seq_num,
                            fragment_id=fragment_id,
                            total_fragments=total_fragments,
                            is_redundant=seq_mod >= self.DATA_UNITS or repeat_index > 0,
                            covert_nonce=fragment_id * self._repeat_count + repeat_index,
                            ip_id_field=ip_id,
                            path_id=path_id,
                            strategy_id=int(self.strategy_id),
                        )
                    )

        self._bytes_encoded += len(data)
        return packets

    def decode(
        self,
        packets: List[bytes],
        metadata: Optional[List[dict]] = None,
    ) -> Optional[bytes]:
        """按 block_id 和 seq_mod 重组，再用冗余和块认证恢复原始数据。"""
        if metadata is None:
            self.last_decode_info = {"complete": False, "reason": "缺少 IP-ID 元数据"}
            return None

        candidates = self._collect_candidates(metadata)
        if not candidates:
            self.last_decode_info = {"complete": False, "reason": "没有策略2候选包"}
            return None

        recovered_blocks: Dict[int, List[int]] = {}
        failed_blocks: List[int] = []
        recovered_by_parity: Dict[int, List[int]] = {}
        auth_failed = 0

        for block_id in sorted(candidates.keys()):
            block_result = self._decode_block(block_id, candidates[block_id])
            if block_result is None:
                failed_blocks.append(block_id)
                auth_failed += 1
                continue
            data_nibbles, recovered_positions = block_result
            recovered_blocks[block_id] = data_nibbles
            if recovered_positions:
                recovered_by_parity[block_id] = recovered_positions

        if 0 not in recovered_blocks:
            self.last_decode_info = {
                "complete": False,
                "reason": "首块未通过认证",
                "candidate_blocks": sorted(candidates.keys()),
                "failed_blocks": failed_blocks,
            }
            return None

        stream_nibbles: List[int] = []
        block_id = 0
        while block_id in recovered_blocks:
            stream_nibbles.extend(recovered_blocks[block_id])
            block_id += 1

        stream = self._nibbles_to_bytes(stream_nibbles)
        if len(stream) < 6 or bytes(stream[:2]) != self.FRAME_MAGIC:
            self.last_decode_info = {
                "complete": False,
                "reason": "帧头认证失败",
                "decoded_blocks": sorted(recovered_blocks.keys()),
                "failed_blocks": failed_blocks,
            }
            return None

        original_len = int.from_bytes(stream[2:6], "big")
        decoded = bytes(stream[6:6 + original_len])
        if len(decoded) != original_len:
            self.last_decode_info = {
                "complete": False,
                "reason": "数据长度不足",
                "expected_len": original_len,
                "actual_len": len(decoded),
                "decoded_blocks": sorted(recovered_blocks.keys()),
                "failed_blocks": failed_blocks,
            }
            return None

        self._bytes_decoded += len(decoded)
        self.last_decode_info = {
            "scheme": "strategy2-ipid-block-mod-nibble-v3",
            "complete": len(failed_blocks) == 0,
            "decoded_blocks": sorted(recovered_blocks.keys()),
            "failed_blocks": failed_blocks,
            "recovered_by_parity": recovered_by_parity,
            "candidate_blocks": sorted(candidates.keys()),
            "auth_failed_blocks": auth_failed,
            "decoded_bytes": len(decoded),
            "repeat_count": self._repeat_count,
            "note": "没有 fragment_id 元数据时，block_mod 支持 16 个块内的乱序重组；当前中期测试数据规模在该范围内。",
        }
        return decoded

    def get_metrics(self, network_state: PathState) -> StrategyMetrics:
        """估计当前网络状态下该策略的性能指标。"""
        useful_ratio = (self.DATA_UNITS / self.BLOCK_UNITS * 0.5) / self._repeat_count
        capacity = 100.0 * useful_ratio

        covertness = 0.58 if network_state.bw_utilization > 0.5 else 0.45
        max_tolerable_loss = 0.25
        if network_state.loss_rate <= 0.03:
            reliability = 0.97
        elif network_state.loss_rate <= max_tolerable_loss:
            reliability = 0.90 - network_state.loss_rate
        else:
            reliability = max(0.15, 0.55 * (max_tolerable_loss / max(network_state.loss_rate, 0.01)))

        return StrategyMetrics(
            covertness_score=covertness,
            capacity_bps=capacity,
            reliability_score=max(0.0, min(1.0, reliability)),
            delay_tolerance_ms=150.0,
            loss_tolerance=max_tolerable_loss,
        )

    def _split_blocks(self, framed_nibbles: List[int]) -> List[List[int]]:
        """把帧数据切成 12 个半字节一组，不足部分用 0 填充。"""
        blocks: List[List[int]] = []
        for offset in range(0, len(framed_nibbles), self.DATA_UNITS):
            chunk = list(framed_nibbles[offset:offset + self.DATA_UNITS])
            if len(chunk) < self.DATA_UNITS:
                chunk.extend([0] * (self.DATA_UNITS - len(chunk)))
            blocks.append(chunk)
        return blocks or [[0] * self.DATA_UNITS]

    def _build_parity(self, data_units: List[int]) -> List[int]:
        """每 4 个数据半字节生成 1 个 XOR 校验半字节。"""
        parity = []
        for group in range(self.PARITY_UNITS):
            start = group * 4
            value = 0
            for item in data_units[start:start + 4]:
                value ^= item
            parity.append(value & 0x0F)
        return parity

    def _decode_block(
        self,
        block_id: int,
        candidates: Dict[int, List[Strategy2Candidate]],
    ) -> Optional[tuple[List[int], List[int]]]:
        """恢复单个块，成功时返回 12 个数据半字节和被冗余恢复的位置。"""
        auth_values = [c.plain_nibble for c in candidates.get(self.AUTH_SEQ, [])]
        if not auth_values:
            return None

        data_units: List[Optional[int]] = [None] * self.DATA_UNITS
        parity_units: List[Optional[int]] = [None] * self.PARITY_UNITS

        for seq_mod in range(self.DATA_UNITS):
            values = candidates.get(seq_mod, [])
            if values:
                data_units[seq_mod] = values[0].plain_nibble

        for parity_index in range(self.PARITY_UNITS):
            seq_mod = self.DATA_UNITS + parity_index
            values = candidates.get(seq_mod, [])
            if values:
                parity_units[parity_index] = values[0].plain_nibble

        recovered_positions: List[int] = []
        for group in range(self.PARITY_UNITS):
            start = group * 4
            group_positions = list(range(start, start + 4))
            missing = [pos for pos in group_positions if data_units[pos] is None]
            if not missing:
                continue
            if len(missing) == 1 and parity_units[group] is not None:
                recovered = parity_units[group]
                for pos in group_positions:
                    if pos != missing[0] and data_units[pos] is not None:
                        recovered ^= data_units[pos]
                data_units[missing[0]] = recovered & 0x0F
                recovered_positions.append(missing[0])
            else:
                return None

        if any(value is None for value in data_units):
            return None

        data_complete = [int(value) & 0x0F for value in data_units]
        computed_parity = self._build_parity(data_complete)
        expected_auth = self._auth_nibble(block_id, data_complete + computed_parity)
        if expected_auth not in auth_values:
            return None
        return data_complete, recovered_positions

    def _collect_candidates(self, metadata: List[dict]) -> Dict[int, Dict[int, List[Strategy2Candidate]]]:
        """从元数据中收集策略2候选片段，并按 block_id/seq_mod 分组。"""
        grouped: Dict[int, Dict[int, List[Strategy2Candidate]]] = {}
        for meta in metadata:
            ip_id = meta.get("ip_id")
            if ip_id is None:
                continue
            parsed = self._unpack_ip_id(int(ip_id))
            if parsed is None:
                continue

            fragment_id = meta.get("fragment_id", meta.get("covert_nonce", meta.get("nonce")))
            if fragment_id is not None:
                block_id = int(fragment_id) // self.BLOCK_UNITS
                self._try_add_candidate(grouped, block_id, parsed["seq_mod"], parsed["cipher_value"], int(ip_id))
                continue

            for block_mod in range(self.MAX_BLOCKS_WITHOUT_FRAGMENT_ID):
                self._try_add_candidate(grouped, block_mod, parsed["seq_mod"], parsed["cipher_value"], int(ip_id))
        return grouped

    def _try_add_candidate(
        self,
        grouped: Dict[int, Dict[int, List[Strategy2Candidate]]],
        block_id: int,
        seq_mod: int,
        cipher_value: int,
        ip_id: int,
    ) -> None:
        """尝试用指定块号解密片段，块号校验通过才加入候选集合。"""
        block_mod = block_id & 0x0F
        plain_value = cipher_value ^ self._keystream_byte(block_mod, seq_mod)
        if ((plain_value >> 4) & 0x0F) != block_mod:
            return
        candidate = Strategy2Candidate(
            block_id=block_id,
            seq_mod=seq_mod,
            plain_nibble=plain_value & 0x0F,
            ip_id=ip_id,
            block_mod=block_mod,
        )
        grouped.setdefault(block_id, {}).setdefault(seq_mod, []).append(candidate)

    def _pack_ip_id(self, seq_mod: int, cipher_value: int) -> int:
        """按统一 IP-ID 候选头格式打包策略2片段。"""
        return (
            STRATEGY2_VALID_MASK
            | ((int(self.strategy_id) & 0x07) << STRATEGY2_STRATEGY_SHIFT)
            | ((seq_mod & 0x0F) << STRATEGY2_SEQ_SHIFT)
            | (cipher_value & 0xFF)
        )

    def _unpack_ip_id(self, ip_id: int) -> Optional[dict]:
        """解析候选 IP-ID；这里只做初筛，最终仍以块认证为准。"""
        if (ip_id & STRATEGY2_VALID_MASK) == 0:
            return None
        strategy_id = (ip_id & STRATEGY2_STRATEGY_MASK) >> STRATEGY2_STRATEGY_SHIFT
        if strategy_id != int(self.strategy_id):
            return None
        return {
            "strategy_id": strategy_id,
            "seq_mod": (ip_id & STRATEGY2_SEQ_MASK) >> STRATEGY2_SEQ_SHIFT,
            "cipher_value": ip_id & STRATEGY2_VALUE_MASK,
        }

    def _keystream_byte(self, block_mod: int, seq_mod: int) -> int:
        """生成块内片段的 1 字节密钥流。"""
        material = (
            self._secret_key
            + b"mask"
            + bytes([block_mod & 0x0F, seq_mod & 0x0F, int(self.strategy_id) & 0x07])
        )
        return hashlib.blake2s(material, digest_size=1).digest()[0]

    def _auth_nibble(self, block_id: int, plain_units: List[int]) -> int:
        """生成 4 bit 块认证值，用于过滤普通业务包误判和错误重组。"""
        material = (
            self._secret_key
            + b"auth"
            + int(block_id & 0xFFFFFFFF).to_bytes(4, "big")
            + bytes(value & 0x0F for value in plain_units)
        )
        return hashlib.blake2s(material, digest_size=1).digest()[0] & 0x0F

    @staticmethod
    def _bytes_to_nibbles(data: bytes) -> List[int]:
        """把字节流拆成高半字节、低半字节序列。"""
        nibbles: List[int] = []
        for value in data:
            nibbles.append((value >> 4) & 0x0F)
            nibbles.append(value & 0x0F)
        return nibbles

    @staticmethod
    def _nibbles_to_bytes(nibbles: List[int]) -> bytes:
        """把半字节序列合并回字节流，奇数长度时低半字节补 0。"""
        output = bytearray()
        padded = list(nibbles)
        if len(padded) % 2:
            padded.append(0)
        for index in range(0, len(padded), 2):
            output.append(((padded[index] & 0x0F) << 4) | (padded[index + 1] & 0x0F))
        return bytes(output)
