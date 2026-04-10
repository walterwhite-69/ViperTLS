import hashlib
from typing import Optional

_GREASE: frozenset = frozenset({
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
})

_EXT_SNI = 0
_EXT_SUPPORTED_VERSIONS = 43
_TLS_VERSION_MAP = {769: "10", 770: "11", 771: "12", 772: "13"}
_PSEUDO_HEADERS = frozenset({":method", ":authority", ":scheme", ":path", ":status"})
_EXCLUDE_JA4H = frozenset({"cookie", "referer"})


def _sha256_12(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()[:12]


def _tls_version_tag(tls_version_int: int, extension_ids: list) -> str:
    if _EXT_SUPPORTED_VERSIONS in extension_ids:
        return "13"
    return _TLS_VERSION_MAP.get(tls_version_int, "12")


def _alpn_tag(alpn: list) -> str:
    if not alpn:
        return "00"
    first = alpn[0]
    if first == "h2":
        return "h2"
    if first == "h3":
        return "h3"
    if first.startswith("http/1"):
        return "h1"
    return (first[:2] + "00")[:2]


def compute_ja4(
    tls_version: int,
    cipher_ids: list,
    extension_ids: list,
    alpn: list,
    sni: bool = True,
) -> str:
    version_tag = _tls_version_tag(tls_version, extension_ids)
    sni_tag = "d" if sni else "i"

    filtered_ciphers = [c for c in cipher_ids if c not in _GREASE]
    filtered_exts = [e for e in extension_ids if e not in _GREASE]

    cipher_count = str(len(filtered_ciphers)).zfill(2)
    ext_count = str(len(filtered_exts)).zfill(2)
    alpn_tag = _alpn_tag(alpn)

    sorted_ciphers = sorted(filtered_ciphers)
    cipher_str = ",".join(str(c) for c in sorted_ciphers)
    ciphers_hash = _sha256_12(cipher_str) if cipher_str else "0" * 12

    sorted_exts = sorted(e for e in filtered_exts if e != _EXT_SNI)
    ext_str = ",".join(str(e) for e in sorted_exts)
    exts_hash = _sha256_12(ext_str) if ext_str else "0" * 12

    return f"t{version_tag}{sni_tag}{cipher_count}{ext_count}{alpn_tag}_{ciphers_hash}_{exts_hash}"


def compute_ja4_r(
    tls_version: int,
    cipher_ids: list,
    extension_ids: list,
    alpn: list,
    sni: bool = True,
) -> str:
    version_tag = _tls_version_tag(tls_version, extension_ids)
    sni_tag = "d" if sni else "i"

    filtered_ciphers = [c for c in cipher_ids if c not in _GREASE]
    filtered_exts = [e for e in extension_ids if e not in _GREASE]

    cipher_count = str(len(filtered_ciphers)).zfill(2)
    ext_count = str(len(filtered_exts)).zfill(2)
    alpn_tag = _alpn_tag(alpn)

    sorted_ciphers = sorted(filtered_ciphers)
    cipher_str = ",".join(str(c) for c in sorted_ciphers)

    sorted_exts = sorted(e for e in filtered_exts if e != _EXT_SNI)
    ext_str = ",".join(str(e) for e in sorted_exts)

    return f"t{version_tag}{sni_tag}{cipher_count}{ext_count}{alpn_tag}_{cipher_str}_{ext_str}"


def compute_ja4h(
    method: str,
    http_version: str,
    headers: list,
) -> str:
    method_tag = (method[:2]).lower().ljust(2, "x")

    if "3" in http_version:
        version_tag = "30"
    elif "2" in http_version:
        version_tag = "20"
    else:
        version_tag = "11"

    has_cookie = any(k.lower() == "cookie" for k, _ in headers)
    has_referer = any(k.lower() == "referer" for k, _ in headers)
    cookie_tag = "c" if has_cookie else "n"
    referer_tag = "r" if has_referer else "n"

    regular_headers = [
        (k, v) for k, v in headers
        if k.lower() not in _PSEUDO_HEADERS and k.lower() not in _EXCLUDE_JA4H
    ]

    header_count = str(len(regular_headers)).zfill(2)

    accept_lang = ""
    for k, v in headers:
        if k.lower() == "accept-language":
            accept_lang = v
            break
    first_lang = accept_lang.split(",")[0].split(";")[0].strip().replace("-", "")
    lang_tag = (first_lang[:4]).ljust(4, "0") if first_lang else "0000"

    fields_str = ",".join(k.lower() for k, _ in regular_headers)
    values_str = ",".join(f"{k.lower()}={v}" for k, v in regular_headers)

    fields_hash = _sha256_12(fields_str) if fields_str else "0" * 12
    values_hash = _sha256_12(values_str) if values_str else "0" * 12

    return f"{method_tag}{version_tag}{cookie_tag}{referer_tag}{header_count}{lang_tag}_{fields_hash}_{values_hash}"


def compute_ja4s(
    tls_version_str: str,
    cipher_name: str,
    cipher_id: Optional[int] = None,
    extension_ids: Optional[list] = None,
) -> str:
    version_map = {
        "TLSv1.3": "13", "TLSv1.2": "12", "TLSv1.1": "11", "TLSv1": "10",
        "TLSv1.0": "10",
    }
    version_tag = version_map.get(tls_version_str, "13")

    if cipher_id is not None:
        cipher_hex = format(cipher_id, "04x")
    else:
        cipher_hex = "0000"

    if extension_ids:
        filtered = [e for e in extension_ids if e not in _GREASE]
        ext_count = str(len(filtered)).zfill(2)
        sorted_exts = sorted(filtered)
        ext_str = ",".join(str(e) for e in sorted_exts)
        ext_hash = _sha256_12(ext_str) if ext_str else "0" * 12
    else:
        ext_count = "00"
        ext_hash = "0" * 12

    return f"t{version_tag}d{ext_count}_{cipher_hex}_{ext_hash}"


def compute_ja4l(connect_ms: float, handshake_ms: float) -> str:
    return f"{round(connect_ms)}_{round(handshake_ms)}"


def ja4_from_preset(preset_ja3: str, alpn: list, sni: bool = True) -> tuple:
    from .ja3 import parse_ja3
    try:
        spec = parse_ja3(preset_ja3)
        ja4 = compute_ja4(spec.tls_version, spec.cipher_ids, spec.extension_ids, alpn, sni)
        ja4_r = compute_ja4_r(spec.tls_version, spec.cipher_ids, spec.extension_ids, alpn, sni)
        return ja4, ja4_r
    except Exception:
        return "", ""
