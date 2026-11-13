"""Генерация ключей без внешних зависимостей.

WireGuard и Xray REALITY используют X25519. Если в системе есть `wg`, берём его,
иначе считаем ключи чистым Python (RFC 7748), чтобы админка работала на любом узле.
"""
import base64
import os
import secrets
import shutil
import subprocess
import uuid

_P = 2**255 - 19
_A24 = 121665


def _clamp(k: bytes) -> bytes:
    b = bytearray(k)
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return bytes(b)


def x25519(k: bytes, u: bytes) -> bytes:
    k_int = int.from_bytes(_clamp(k), "little")
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in reversed(range(255)):
        kt = (k_int >> t) & 1
        swap ^= kt
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = kt
        a = x2 + z2
        aa = a * a
        b = x2 - z2
        bb = b * b
        e = aa - bb
        c = x3 + z3
        d = x3 - z3
        da = d * a
        cb = c * b
        x3 = (da + cb) ** 2 % _P
        z3 = x1 * (da - cb) ** 2 % _P
        x2 = aa * bb % _P
        z2 = e * (aa + _A24 * e) % _P
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, _P - 2, _P) % _P).to_bytes(32, "little")


_BASE = (9).to_bytes(32, "little")


def _raw_pair():
    priv = _clamp(os.urandom(32))
    return priv, x25519(priv, _BASE)


def wg_keypair():
    """(private, public) в формате WireGuard (base64)."""
    if shutil.which("wg"):
        priv = subprocess.run(["wg", "genkey"], capture_output=True, text=True, check=True).stdout.strip()
        pub = subprocess.run(["wg", "pubkey"], input=priv, capture_output=True, text=True, check=True).stdout.strip()
        return priv, pub
    priv, pub = _raw_pair()
    return base64.b64encode(priv).decode(), base64.b64encode(pub).decode()


def wg_psk():
    return base64.b64encode(os.urandom(32)).decode()


def reality_keypair():
    """(private, public) в формате Xray REALITY (base64url без '=')."""
    priv, pub = _raw_pair()
    enc = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")
    return enc(priv), enc(pub)


def new_uuid():
    return str(uuid.uuid4())


def short_id():
    return secrets.token_hex(8)
