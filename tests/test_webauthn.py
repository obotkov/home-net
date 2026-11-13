import hashlib
import random
import unittest

from netadmin import webauthn as w


def _der(r, s):
    def i(v):
        b = v.to_bytes((v.bit_length() + 8) // 8, "big")
        return b"\x02" + bytes([len(b)]) + b
    body = i(r) + i(s)
    return b"\x30" + bytes([len(body)]) + body


def _es256_sign(d, msg):
    e = int.from_bytes(hashlib.sha256(msg).digest(), "big")
    while True:
        k = random.randrange(1, w._N)
        r = w._mul(k, w._G)[0] % w._N
        s = pow(k, -1, w._N) * (e + r * d) % w._N
        if r and s:
            return _der(r, s)


def _prime(bits):
    while True:
        n = random.getrandbits(bits) | (1 << bits - 1) | 1
        if all(pow(a, n - 1, n) == 1 for a in (2, 3, 5, 7, 11, 13, 17, 19, 23)):
            return n


class T(unittest.TestCase):
    def test_es256(self):
        d = random.randrange(1, w._N)
        x, y = w._mul(d, w._G)
        sig = _es256_sign(d, b"hello")
        self.assertTrue(w.es256_verify(x, y, b"hello", sig))
        self.assertFalse(w.es256_verify(x, y, b"hellO", sig))

    def test_rs256(self):
        p, q, e = _prime(512), _prime(512), 65537
        n = p * q
        dd = pow(e, -1, (p - 1) * (q - 1))
        k = (n.bit_length() + 7) // 8
        t = w._SHA256_PREFIX + hashlib.sha256(b"msg").digest()
        em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
        sig = pow(int.from_bytes(em, "big"), dd, n).to_bytes(k, "big")
        self.assertTrue(w.rs256_verify(n, e, b"msg", sig))
        self.assertFalse(w.rs256_verify(n, e, b"msg2", sig))

    def test_cbor(self):
        # {1: 2, 3: -7, -2: h'01', "a": [true, null]}
        data = bytes.fromhex("a4010203262141016161" + "82f5f6")
        self.assertEqual(w.cbor_decode(data)[0], {1: 2, 3: -7, -2: b"\x01", "a": [True, None]})

    def test_rpid_mismatch(self):
        ad = hashlib.sha256(b"evil.example").digest() + b"\x05" + b"\x00\x00\x00\x01"
        with self.assertRaises(w.WebAuthnError):
            w._auth_data(ad, "panel.example")


if __name__ == "__main__":
    unittest.main()
