"""
IPv4 Identification 字段隐蔽载荷编解码与轻量扰动。
"""

import hashlib
from typing import List, Optional, Tuple


# IP-ID 字段布局：valid(1) + tag(1) + strategy_id(3) + path_id(3) + encrypted_payload(8)。
IP_ID_VALID_BIT      = 1    # 是否为隐蔽字段。
IP_ID_TAG_BITS       = 1    # 轻量认证位，降低普通 IP-ID 被误判的概率。
IP_ID_STRATEGY_BITS  = 3    # 策略编号，最多支持 0-7 共八类策略。
IP_ID_PATH_BITS      = 3    # 路径编号，最多支持八条路径。
IP_ID_PAYLOAD_BITS   = 8    # 加密后的 1 字节载荷。

# 各字段在 16 bit IPv4 Identification 中的起始位置。
IP_ID_VALID_SHIFT = 15
IP_ID_TAG_SHIFT = 14
IP_ID_STRATEGY_SHIFT = 11
IP_ID_PATH_SHIFT     = 8
IP_ID_PAYLOAD_SHIFT  = 0

IP_ID_VALID_MASK     = 0x8000  # valid 字段掩码。
IP_ID_TAG_MASK       = 0x4000  # tag 字段掩码。
IP_ID_STRATEGY_MASK  = 0x3800  # strategy_id 字段掩码。
IP_ID_PATH_MASK      = 0x0700  # path_id 字段掩码。
IP_ID_PAYLOAD_MASK   = 0x00FF  # encrypted_payload 字段掩码。


class IPIDCodec:
    """
    IPv4 Identification 字段隐蔽载荷编解码器。
    """

    def __init__(self, secret_key: bytes = b"low-altitude-covert-ipid-v1"):
        self.secret_key = secret_key

    def pack_ip_id(
        self,
        strategy_id: int,
        path_id: int,
        data_byte: int,
        nonce: int = 0,
        covert_valid: bool = True,
        **_ignored,
    ) -> int:
        """
        按固定布局封装 IPv4 Identification 字段。
        """
        if not covert_valid:
            return data_byte & 0xFFFF

        cipher_byte = self.encrypt_byte(
            data_byte, nonce=nonce, strategy_id=strategy_id, path_id=path_id)
        tag_bit = self._tag_bit(
            cipher_byte, nonce=nonce, strategy_id=strategy_id, path_id=path_id)

        valid_part = 1 << IP_ID_VALID_SHIFT
        tag_part = tag_bit << IP_ID_TAG_SHIFT
        strategy_part = (strategy_id & 0x07) << IP_ID_STRATEGY_SHIFT
        path_part     = (path_id & 0x07)     << IP_ID_PATH_SHIFT
        payload = cipher_byte & 0xFF

        return valid_part | tag_part | strategy_part | path_part | payload

    def unpack_ip_id(self, ip_id: int, nonce: int = 0) -> dict:
        """
        解析 IPv4 Identification 字段，并校验认证位。
        """
        covert_valid = bool((ip_id & IP_ID_VALID_MASK) >> IP_ID_VALID_SHIFT)
        tag_bit = (ip_id & IP_ID_TAG_MASK) >> IP_ID_TAG_SHIFT
        strategy_id = (ip_id & IP_ID_STRATEGY_MASK) >> IP_ID_STRATEGY_SHIFT
        path_id = (ip_id & IP_ID_PATH_MASK) >> IP_ID_PATH_SHIFT
        cipher_byte = ip_id & IP_ID_PAYLOAD_MASK

        expected_tag = self._tag_bit(
            cipher_byte, nonce=nonce, strategy_id=strategy_id, path_id=path_id)
        tag_valid = bool(covert_valid and tag_bit == expected_tag)
        data_byte = None
        if tag_valid:
            data_byte = self.decrypt_byte(
                cipher_byte, nonce=nonce, strategy_id=strategy_id, path_id=path_id)

        return {
            "covert_valid": covert_valid,
            "tag_valid": tag_valid,
            "tag_bit": tag_bit,
            "strategy_id": strategy_id,
            "path_id": path_id,
            "cipher_byte": cipher_byte,
            "data_byte": data_byte,
        }

    def encrypt_byte(
        self,
        data_byte: int,
        nonce: int = 0,
        strategy_id: int = 0,
        path_id: int = 0,
    ) -> int:
        """使用轻量密钥流加密 1 字节载荷。"""
        return (data_byte & 0xFF) ^ self._keystream_byte(
            nonce=nonce, strategy_id=strategy_id, path_id=path_id)

    def decrypt_byte(
        self,
        cipher_byte: int,
        nonce: int = 0,
        strategy_id: int = 0,
        path_id: int = 0,
    ) -> int:
        """IP-ID 载荷加密采用异或结构，解密与加密相同。"""
        return self.encrypt_byte(
            cipher_byte, nonce=nonce, strategy_id=strategy_id, path_id=path_id)

    def is_covert_ip_id(self, ip_id: int, nonce: int = 0) -> bool:
        """判断一个 IP-ID 是否符合当前隐蔽字段格式。"""
        info = self.unpack_ip_id(ip_id, nonce=nonce)
        return bool(info["covert_valid"] and info["tag_valid"])

    def encode_stream(
        self,
        data: bytes,
        strategy_id: int,
        path_id: int,
    ) -> List[int]:
        """
        把字节流编码为一组 IP-ID 值。
        """
        ip_ids = []
        for i, byte_val in enumerate(data):
            ip_id = self.pack_ip_id(
                strategy_id=strategy_id,
                path_id=path_id,
                data_byte=byte_val,
                nonce=i,
            )
            ip_ids.append(ip_id)
        return ip_ids

    def decode_stream(self, ip_ids: List[int]) -> Tuple[bytes, List[dict]]:
        """
        从一组 IP-ID 值中恢复字节流和解析元数据。
        """
        data_bytes = []
        metadata_list = []

        for i, ip_id in enumerate(ip_ids):
            info = self.unpack_ip_id(ip_id, nonce=i)
            metadata_list.append(info)
            if info["covert_valid"] and info["tag_valid"]:
                data_bytes.append(info["data_byte"])

        return bytes(data_bytes), metadata_list

    def _keystream_byte(self, nonce: int, strategy_id: int, path_id: int) -> int:
        material = (
            self.secret_key
            + int(nonce & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "big")
            + bytes([(strategy_id & 0x07), (path_id & 0x07)])
        )
        return hashlib.blake2s(material, digest_size=1).digest()[0]

    def _tag_bit(self, cipher_byte: int, nonce: int, strategy_id: int, path_id: int) -> int:
        material = (
            self.secret_key
            + b"tag"
            + int(nonce & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "big")
            + bytes([(strategy_id & 0x07), (path_id & 0x07), (cipher_byte & 0xFF)])
        )
        return hashlib.blake2s(material, digest_size=1).digest()[0] & 0x01
