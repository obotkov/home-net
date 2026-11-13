import json
import unittest

from netadmin import server


class ServerTest(unittest.TestCase):
    def test_conf_meta_hides_keys(self):
        meta = server.parse_conf_meta("[Interface]\nPrivateKey = SECRET\nAddress = 10.255.0.0/31\nJc = 5\n"
                                      "[Peer]\nPublicKey = X\nPresharedKey = P\n")
        self.assertEqual(meta, {"Address": "10.255.0.0/31", "Jc": "5"})

    def test_xray_mask_and_summary(self):
        conf = {"inbounds": [{"tag": "in", "port": 443, "protocol": "vless",
                              "settings": {"clients": [{"id": "uuid-secret", "flow": "xtls-rprx-vision", "email": "a@b"}]},
                              "streamSettings": {"security": "reality", "realitySettings": {
                                  "privateKey": "PK", "serverNames": ["www.microsoft.com"], "dest": "www.microsoft.com:443"}}}],
                "outbounds": [{"tag": "direct", "protocol": "freedom"}]}
        masked = json.dumps(server._mask(conf))
        self.assertNotIn("uuid-secret", masked)
        self.assertNotIn('"PK"', masked)
        sm = server.xray_summary(conf, {443})
        self.assertTrue(sm["inbounds"][0]["listening"])
        self.assertEqual(sm["inbounds"][0]["clients"], ["a@b"])


if __name__ == "__main__":
    unittest.main()
