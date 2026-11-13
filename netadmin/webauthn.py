"""Минимальная серверная часть WebAuthn (passkey) без внешних зависимостей.

Поддерживаются ключи ES256 (P-256, alg -7: почти все passkey — Apple, Google, Android, YubiKey)
и RS256 (alg -257: Windows Hello). Аттестация не проверяется ("none"), как у большинства сайтов.
"""
import base64
import hashlib
import json
import os
import struct


class WebAuthnError(ValueError):
    pass


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def challenge() -> str:
    return b64u(os.urandom(32))


# ---------------------------------------------------------------- CBOR (только то, что нужно WebAuthn)
def cbor_decode(data: bytes, pos: int = 0):
    ib = data[pos]
    mt, ai = ib >> 5, ib & 0x1F
    pos += 1
    if ai < 24:
        val = ai
    elif ai in (24, 25, 26, 27):
        n = 1 << (ai - 24)
        val = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    else:
        raise WebAuthnError("CBOR: неподдерживаемая длина")
    if mt == 0:
        return val, pos
    if mt == 1:
        return -1 - val, pos
    if mt == 2:
        return data[pos:pos + val], pos + val
    if mt == 3:
        return data[pos:pos + val].decode(), pos + val
    if mt == 4:
        out = []
        for _ in range(val):
            item, pos = cbor_decode(data, pos)
            out.append(item)
        return out, pos
    if mt == 5:
        out = {}
        for _ in range(val):
            k, pos = cbor_decode(data, pos)
            v, pos = cbor_decode(data, pos)
            out[k] = v
        return out, pos
    if mt == 7:
        return {20: False, 21: True, 22: None}.get(ai), pos
    raise WebAuthnError("CBOR: неподдерживаемый тип")


# ---------------------------------------------------------------- P-256 ECDSA
_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_A = _P - 3
_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
      0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)


def _add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % _P == 0:
        return None
    if p == q:
        lam = (3 * p[0] * p[0] + _A) * pow(2 * p[1], -1, _P) % _P
    else:
        lam = (q[1] - p[1]) * pow(q[0] - p[0], -1, _P) % _P
    x = (lam * lam - p[0] - q[0]) % _P
    return x, (lam * (p[0] - x) - p[1]) % _P


def _mul(k, p):
    r = None
    while k:
        if k & 1:
            r = _add(r, p)
        p = _add(p, p)
        k >>= 1
    return r


def _on_curve(pt):
    x, y = pt
    return (y * y - (x * x * x + _A * x + _B)) % _P == 0


def _der_sig(sig: bytes):
    # SEQUENCE { INTEGER r, INTEGER s }
    if len(sig) < 8 or sig[0] != 0x30:
        raise WebAuthnError("подпись: не DER")
    pos = 2 if sig[1] < 0x80 else 2 + (sig[1] & 0x7F)
    vals = []
    for _ in range(2):
        if sig[pos] != 0x02:
            raise WebAuthnError("подпись: не DER")
        ln = sig[pos + 1]
        vals.append(int.from_bytes(sig[pos + 2:pos + 2 + ln], "big"))
        pos += 2 + ln
    return vals


def es256_verify(x: int, y: int, msg: bytes, sig: bytes) -> bool:
    if not _on_curve((x, y)):
        return False
    r, s = _der_sig(sig)
    if not (1 <= r < _N and 1 <= s < _N):
        return False
    e = int.from_bytes(hashlib.sha256(msg).digest(), "big")
    w = pow(s, -1, _N)
    pt = _add(_mul(e * w % _N, _G), _mul(r * w % _N, (x, y)))
    return pt is not None and pt[0] % _N == r


# ---------------------------------------------------------------- RS256 (PKCS#1 v1.5)
_SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


def rs256_verify(n: int, e: int, msg: bytes, sig: bytes) -> bool:
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        return False
    em = pow(int.from_bytes(sig, "big"), e, n).to_bytes(k, "big")
    t = _SHA256_PREFIX + hashlib.sha256(msg).digest()
    return em == b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t


# ---------------------------------------------------------------- COSE key
def parse_cose_key(cose: dict) -> dict:
    alg = cose.get(3)
    if alg == -7 and cose.get(1) == 2 and cose.get(-1) == 1:
        return {"alg": -7, "x": cose[-2].hex(), "y": cose[-3].hex()}
    if alg == -257 and cose.get(1) == 3:
        return {"alg": -257, "n": cose[-1].hex(), "e": cose[-2].hex()}
    raise WebAuthnError(f"неподдерживаемый тип ключа (alg {alg}); нужен ES256 или RS256")


def verify_sig(key: dict, msg: bytes, sig: bytes) -> bool:
    if key["alg"] == -7:
        return es256_verify(int(key["x"], 16), int(key["y"], 16), msg, sig)
    if key["alg"] == -257:
        return rs256_verify(int(key["n"], 16), int(key["e"], 16), msg, sig)
    return False


# ---------------------------------------------------------------- проверки
def _client_data(b64: str, typ: str, chal: str, origin: str) -> bytes:
    raw = unb64u(b64)
    cd = json.loads(raw)
    if cd.get("type") != typ:
        raise WebAuthnError("неверный тип операции")
    if cd.get("challenge") != chal:
        raise WebAuthnError("challenge не совпадает (устарел?)")
    if cd.get("origin") != origin:
        raise WebAuthnError(f"origin {cd.get('origin')} не совпадает с {origin}")
    return raw


def _auth_data(ad: bytes, rp_id: str):
    if len(ad) < 37:
        raise WebAuthnError("authenticatorData слишком короткие")
    if ad[:32] != hashlib.sha256(rp_id.encode()).digest():
        raise WebAuthnError("ключ создан для другого домена")
    flags = ad[32]
    if not flags & 0x01:
        raise WebAuthnError("нет подтверждения присутствия пользователя")
    return flags, struct.unpack(">I", ad[33:37])[0]


def verify_registration(resp: dict, chal: str, origin: str, rp_id: str) -> dict:
    _client_data(resp["clientDataJSON"], "webauthn.create", chal, origin)
    att, _ = cbor_decode(unb64u(resp["attestationObject"]))
    ad = att["authData"]
    flags, count = _auth_data(ad, rp_id)
    if not flags & 0x40:
        raise WebAuthnError("нет данных ключа")
    cred_len = struct.unpack(">H", ad[53:55])[0]
    cred_id = ad[55:55 + cred_len]
    cose, _ = cbor_decode(ad, 55 + cred_len)
    return {"id": b64u(cred_id), "key": parse_cose_key(cose), "sign_count": count,
            "uv": bool(flags & 0x04)}


def verify_assertion(resp: dict, cred: dict, chal: str, origin: str, rp_id: str) -> int:
    cd_raw = _client_data(resp["clientDataJSON"], "webauthn.get", chal, origin)
    ad = unb64u(resp["authenticatorData"])
    _, count = _auth_data(ad, rp_id)
    if not verify_sig(cred["key"], ad + hashlib.sha256(cd_raw).digest(), unb64u(resp["signature"])):
        raise WebAuthnError("подпись не прошла проверку")
    if count and cred.get("sign_count") and count <= cred["sign_count"]:
        raise WebAuthnError("счётчик подписи не вырос: возможно, ключ скопирован")
    return count
