from dataclasses import dataclass, field
from typing import List, Set


CIPHER_MAP: dict[int, str] = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x002F: "AES128-SHA",
    0x0035: "AES256-SHA",
    0x003C: "AES128-SHA256",
    0x003D: "AES256-SHA256",
    0x009C: "AES128-GCM-SHA256",
    0x009D: "AES256-GCM-SHA384",
    0x000A: "DES-CBC3-SHA",
    0x0033: "DHE-RSA-AES128-SHA",
    0x0039: "DHE-RSA-AES256-SHA",
    0x0067: "DHE-RSA-AES128-SHA256",
    0x006B: "DHE-RSA-AES256-SHA256",
    0x009E: "DHE-RSA-AES128-GCM-SHA256",
    0x009F: "DHE-RSA-AES256-GCM-SHA384",
    0xC002: "ECDH-ECDSA-RC4-SHA",
    0xC009: "ECDHE-ECDSA-AES128-SHA",
    0xC00A: "ECDHE-ECDSA-AES256-SHA",
    0xC013: "ECDHE-RSA-AES128-SHA",
    0xC014: "ECDHE-RSA-AES256-SHA",
    0xC023: "ECDHE-ECDSA-AES128-SHA256",
    0xC024: "ECDHE-ECDSA-AES256-SHA384",
    0xC027: "ECDHE-RSA-AES128-SHA256",
    0xC028: "ECDHE-RSA-AES256-SHA384",
    0xC02B: "ECDHE-ECDSA-AES128-GCM-SHA256",
    0xC02C: "ECDHE-ECDSA-AES256-GCM-SHA384",
    0xC02F: "ECDHE-RSA-AES128-GCM-SHA256",
    0xC030: "ECDHE-RSA-AES256-GCM-SHA384",
    0xC031: "ECDH-RSA-AES128-GCM-SHA256",
    0xC032: "ECDH-RSA-AES256-GCM-SHA384",
    0xCCA8: "ECDHE-RSA-CHACHA20-POLY1305",
    0xCCA9: "ECDHE-ECDSA-CHACHA20-POLY1305",
    0xCCAA: "DHE-RSA-CHACHA20-POLY1305",
}

TLS13_CIPHER_IDS: Set[int] = {0x1301, 0x1302, 0x1303}

CURVE_MAP: dict[int, str] = {
    1: "sect163k1",
    2: "sect163r1",
    3: "sect163r2",
    4: "sect193r1",
    5: "sect193r2",
    6: "sect233k1",
    7: "sect233r1",
    8: "sect239k1",
    9: "sect283k1",
    10: "sect283r1",
    11: "sect409k1",
    12: "sect409r1",
    13: "sect571k1",
    14: "sect571r1",
    15: "secp160k1",
    16: "secp160r1",
    17: "secp160r2",
    18: "secp192k1",
    19: "secp192r1",
    20: "secp224k1",
    21: "secp224r1",
    22: "secp256k1",
    23: "P-256",
    24: "P-384",
    25: "P-521",
    29: "X25519",
    30: "X448",
    256: "ffdhe2048",
    257: "ffdhe3072",
    258: "ffdhe4096",
    259: "ffdhe6144",
    260: "ffdhe8192",
}


@dataclass
class JA3Spec:
    tls_version: int
    cipher_ids: List[int]
    extension_ids: List[int]
    curve_ids: List[int]
    point_formats: List[int]
    tls12_ciphers: List[str] = field(default_factory=list)
    tls13_ciphers: List[str] = field(default_factory=list)
    curve_names: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        for cid in self.cipher_ids:
            name = CIPHER_MAP.get(cid)
            if name is None:
                continue
            if cid in TLS13_CIPHER_IDS:
                self.tls13_ciphers.append(name)
            else:
                self.tls12_ciphers.append(name)

        for cid in self.curve_ids:
            name = CURVE_MAP.get(cid)
            if name:
                self.curve_names.append(name)


def _split_ids(segment: str) -> List[int]:
    if not segment:
        return []
    return [int(x) for x in segment.split("-") if x]


def parse_ja3(ja3: str) -> JA3Spec:
    parts = ja3.split(",")
    if len(parts) != 5:
        raise ValueError(f"Invalid JA3 string: expected 5 comma-separated fields, got {len(parts)}")

    return JA3Spec(
        tls_version=int(parts[0]),
        cipher_ids=_split_ids(parts[1]),
        extension_ids=_split_ids(parts[2]),
        curve_ids=_split_ids(parts[3]),
        point_formats=_split_ids(parts[4]),
    )
