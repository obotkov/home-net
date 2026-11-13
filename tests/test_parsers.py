import unittest
from netadmin import collectors as c

class T(unittest.TestCase):
    def test_wg(self):
        d = c.parse_wg_dump("wg-ams\tPRIV\tPUB\t0\toff\n"
                            "wg-ams\tPEER\tPSK\t127.0.0.1:20001\t0.0.0.0/0\t1700000000\t1234\t5678\t25\n")
        self.assertEqual(d["wg-ams"]["peers"][0]["rx"], 1234)
        self.assertEqual(d["wg-ams"]["peers"][0]["endpoint"], "127.0.0.1:20001")

    def test_ospf(self):
        txt = ("ospf1:\nRouter ID   \tPri\t     State     \tDTime\tInterface  Router IP\n"
               "10.254.0.2\t  1\tFull/PtP  \t17.345\twg-ams     10.255.0.0\n")
        n = c.parse_ospf_neighbors(txt)
        self.assertEqual(n, [{"router_id": "10.254.0.2", "state": "Full/PtP", "dead": "17.345",
                              "iface": "wg-ams", "ip": "10.255.0.0"}])

    def test_routes(self):
        txt = ("Table master4:\n"
               "192.168.1.0/24       unicast [ospf1 10:22:33.123] * I (150/10) [10.254.0.1]\n"
               "\tdev br-lan\n"
               "10.255.0.2/31        unicast [ospf1 10:22:33.123] * I (150/20) [10.254.0.3]\n"
               "\tvia 10.255.0.0 on wg-ams\n"
               "                     unicast [ospf1 10:22:34.000] I (150/30) [10.254.0.3]\n"
               "\tvia 10.255.0.4 on wg-fra\n")
        r = c.parse_bird_routes(txt)
        self.assertEqual(len(r), 3)
        self.assertEqual(r[0]["iface"], "br-lan")
        self.assertEqual((r[1]["via"], r[1]["iface"], r[1]["primary"]), ("10.255.0.0", "wg-ams", True))
        self.assertEqual((r[2]["net"], r[2]["primary"], r[2]["iface"]), ("10.255.0.2/31", False, "wg-fra"))

    def test_leases(self):
        d = c.parse_leases("1700000000 aa:bb:cc:dd:ee:ff 192.168.1.10 gpu-pc 01:aa\n1 11:22:33:44:55:66 192.168.1.11 * *\n")
        self.assertEqual(d["192.168.1.10"]["hostname"], "gpu-pc")
        self.assertIsNone(d["192.168.1.11"]["hostname"])

if __name__ == "__main__":
    unittest.main()
