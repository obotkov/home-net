import os
import tempfile
import unittest

from netadmin import generator
from netadmin.store import Store


class KeeneticTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.s = Store(os.path.join(self.d, "s.json"))
        self.s.update_home({"mode": "keenetic"})
        self.v = self.s.add_vps({"name": "ams", "public_ip": "203.0.113.7"})

    def test_asc_params_match(self):
        a = self.v["awg"]
        self.assertNotEqual(a["s1"] + 56, a["s2"])
        self.assertEqual(len({a["h1"], a["h2"], a["h3"], a["h4"]}), 4)
        k = generator.keenetic_conf(self.s.home, self.v)
        srv = generator.awg_vps_conf(self.s.home, self.v)
        for key in ("Jc", "S1", "S2", "H1", "H4"):
            line = next(x for x in k.splitlines() if x.startswith(key + " "))
            self.assertIn(line, srv)
        self.assertIn(f"Endpoint = 203.0.113.7:{a['port']}", k)
        self.assertIn(self.s.home["lan_cidr"], srv)

    def test_bootstrap_dispatch(self):
        self.assertIn("amneziawg", generator.bootstrap_for(self.s.home, self.v))
        self.assertNotIn("bird", generator.bootstrap_for(self.s.home, self.v))
        files = generator.all_files(self.s.home, self.s.vps, self.v)
        self.assertIn("ams/keenetic-ams.conf", files)

    def test_bad_mode(self):
        with self.assertRaises(ValueError):
            self.s.update_home({"mode": "openwrt"})


if __name__ == "__main__":
    unittest.main()
