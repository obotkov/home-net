"""Сбор состояния домашнего узла: WireGuard, OSPF (birdc), маршруты, устройства LAN.

Если нужных утилит нет (или NETADMIN_DEMO=1), отдаём правдоподобные демо-данные,
чтобы интерфейс можно было посмотреть где угодно.
"""
import json
import os
import random
import re
import shutil
import subprocess
import time

from .generator import home_iface

LEASE_FILES = ["/tmp/dhcp.leases", "/var/lib/misc/dnsmasq.leases", "/var/lib/dhcp/dhcpd.leases"]


def demo_mode():
    return os.environ.get("NETADMIN_DEMO") == "1" or not (shutil.which("wg") or shutil.which("awg"))


def _run(cmd, timeout=5):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout if r.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


# ---------------------------------------------------------------- parsers
def parse_wg_dump(text):
    """`wg show all dump` -> {iface: {listen_port, peers:[...]}}"""
    res = {}
    for line in text.splitlines():
        f = line.split("\t")
        if f[0] not in res and len(f) >= 5:  # интерфейс (у awg после fwmark идут параметры ASC)
            res[f[0]] = {"listen_port": int(f[3]) if f[3].isdigit() else None, "peers": []}
        elif len(f) >= 9 and f[0] in res:
            res[f[0]]["peers"].append({
                "public_key": f[1], "endpoint": None if f[3] == "(none)" else f[3],
                "allowed_ips": f[4], "latest_handshake": int(f[5]),
                "rx": int(f[6]), "tx": int(f[7]),
            })
    return res


def parse_ospf_neighbors(text):
    res = []
    for line in text.splitlines():
        m = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\S+)\s+([\d.]+)\s+(\S+)\s+(\S+)", line.strip())
        if m:
            res.append({"router_id": m[1], "state": m[3], "dead": m[4], "iface": m[5], "ip": m[6]})
    return res


def parse_bird_routes(text):
    """`birdc -r show route all`-подобный вывод -> [{net, proto, via, iface, primary}]"""
    routes, cur = [], None
    for line in text.splitlines():
        m = re.match(r"^(\S+/\d+)?\s+(\w+)\s+\[(\S+)\s+[^\]]*\]\s*(\*)?", line)
        if m and "[" in line and not line.startswith("\t"):
            net = m[1] or (cur["net"] if cur else "")
            cur = {"net": net, "type": m[2], "proto": m[3], "primary": bool(m[4]), "via": None, "iface": None}
            mm = re.search(r"\((\d+)(?:/(\d+))?\)", line)
            cur["metric"] = mm[0].strip("()") if mm else ""
            routes.append(cur)
            continue
        m = re.match(r"^\s+via (\S+) on (\S+)", line)
        if m and cur:
            cur["via"], cur["iface"] = m[1], m[2]
            continue
        m = re.match(r"^\s+dev (\S+)", line)
        if m and cur:
            cur["iface"] = m[1]
    return routes


def parse_leases(text):
    names = {}
    for line in text.splitlines():
        f = line.split()
        if len(f) >= 4 and re.match(r"^[0-9a-f:]{17}$", f[1].lower()):
            names[f[2]] = {"mac": f[1].lower(), "hostname": None if f[3] == "*" else f[3]}
    return names


# ---------------------------------------------------------------- live collection
def collect(store):
    if demo_mode():
        return _demo(store)
    home = store.home
    wg = parse_wg_dump(_run(["wg", "show", "all", "dump"]))
    if shutil.which("awg"):
        wg.update(parse_wg_dump(_run(["awg", "show", "all", "dump"])))
    ospf = parse_ospf_neighbors(_run(["birdc", "-r", "show", "ospf", "neighbors"]))
    routes = parse_bird_routes(_run(["birdc", "-r", "show", "route"]))
    leases = {}
    for p in LEASE_FILES:
        if os.path.exists(p):
            with open(p) as f:
                leases.update(parse_leases(f.read()))
    devices = []
    try:  # в режиме Keenetic панель стоит на VPS и домашней LAN не видит
        neigh = [] if home.get("mode") == "keenetic" else \
            json.loads(_run(["ip", "-j", "neigh", "show", "dev", home["lan_if"]]) or "[]")
    except json.JSONDecodeError:
        neigh = []
    seen = set()
    for n in neigh:
        ip = n.get("dst")
        if not ip or ":" in ip or ip in seen:
            continue
        seen.add(ip)
        st = n.get("state", [])
        lease = leases.get(ip, {})
        devices.append({"ip": ip, "mac": n.get("lladdr") or lease.get("mac"), "hostname": lease.get("hostname"),
                        "online": any(s in ("REACHABLE", "DELAY", "PROBE", "STALE") for s in st),
                        "state": ",".join(st)})
    for ip, lease in leases.items():
        if ip not in seen:
            devices.append({"ip": ip, "mac": lease["mac"], "hostname": lease["hostname"], "online": False,
                            "state": "lease"})
    services = {s: _run(["systemctl", "is-active", s]).strip() or "unknown"
                for s in ("xray", "bird", "awg-quick@awg-home")}
    return _assemble(store, wg, ospf, routes, devices, services, demo=False)


def _assemble(store, wg, ospf, routes, devices, services, demo):
    now = int(time.time())
    links = []
    keenetic = store.home.get("mode") == "keenetic"
    for v in store.vps:
        if keenetic:
            links.append(_keenetic_link(v, wg, now))
            continue
        iface = home_iface(v)
        w = wg.get(iface)
        peer = w["peers"][0] if w and w["peers"] else None
        hs = peer["latest_handshake"] if peer else 0
        nb = next((n for n in ospf if n["iface"] == iface), None)
        wg_ok = bool(hs) and now - hs < 180
        ospf_ok = bool(nb) and nb["state"].lower().startswith("full")
        links.append({
            "id": v["id"], "name": v["name"], "label": v["label"], "public_ip": v["public_ip"], "iface": iface,
            "tunnel": f"{v['home_tun_ip']} ↔ {v['vps_tun_ip']}", "cost": v["cost"],
            "wg_up": w is not None, "handshake_ago": (now - hs) if hs else None,
            "rx": peer["rx"] if peer else 0, "tx": peer["tx"] if peer else 0,
            "ospf_state": nb["state"] if nb else None,
            "status": "up" if wg_ok and ospf_ok else ("degraded" if wg_ok or ospf_ok else "down"),
            "deploy": v.get("deploy", {}).get("status", "never"),
        })
    devices.sort(key=lambda d: tuple(int(x) for x in d["ip"].split(".")))
    return {
        "demo": demo, "time": now,
        "home": {k: store.home.get(k) for k in ("name", "lan_if", "lan_cidr", "router_id", "wg_mtu", "ospf_cost", "mode")},
        "services": services, "links": links, "ospf_neighbors": ospf, "routes": routes, "devices": devices,
        "unknown_wg": [i for i in wg if i.startswith("wg-") and i not in {home_iface(v) for v in store.vps}],
    }


def _keenetic_link(v, wg, now):
    """Режим Keenetic: статус видно только для VPS, на котором стоит сама панель
    (там есть пир с ключом роутера). Для остальных VPS — «неизвестно»."""
    peer = next((p for w in wg.values() for p in w["peers"] if p["public_key"] == v["wg"]["home_pub"]), None)
    hs = peer["latest_handshake"] if peer else 0
    status = "unknown" if not peer else ("up" if hs and now - hs < 180 else "down")
    return {
        "id": v["id"], "name": v["name"], "label": v["label"], "public_ip": v["public_ip"], "iface": "awg-home",
        "tunnel": f"{v['home_tun_ip']} ↔ {v['vps_tun_ip']}", "cost": v["cost"],
        "wg_up": peer is not None, "handshake_ago": (now - hs) if hs else None,
        "rx": peer["rx"] if peer else 0, "tx": peer["tx"] if peer else 0,
        "ospf_state": None, "status": status, "deploy": v.get("deploy", {}).get("status", "never"),
    }


# ---------------------------------------------------------------- demo
_DEMO_DEVICES = [
    ("192.168.1.1", "router"), ("192.168.1.10", "gpu-pc"), ("192.168.1.11", "nas"),
    ("192.168.1.20", "pi-gateway"), ("192.168.1.35", "tv-livingroom"), ("192.168.1.42", "alex-phone"),
    ("192.168.1.43", "laptop"), ("192.168.1.60", "printer"), ("192.168.1.77", None),
]


def _demo(store):
    rnd = random.Random(42)
    now = int(time.time())
    net = store.home["lan_cidr"].rsplit(".", 1)[0]
    devices = []
    for ip, name in _DEMO_DEVICES:
        ip = net + "." + ip.rsplit(".", 1)[1]
        mac = ":".join(f"{rnd.randrange(256):02x}" for _ in range(6))
        devices.append({"ip": ip, "mac": mac, "hostname": name, "online": name not in ("printer", None),
                        "state": "REACHABLE" if name not in ("printer", None) else "STALE"})
    wg, ospf, routes = {}, [], [
        {"net": store.home["lan_cidr"], "type": "unicast", "proto": "ospf1", "primary": True, "via": None,
         "iface": store.home["lan_if"], "metric": "10"}]
    for i, v in enumerate(store.vps):
        iface = home_iface(v)
        healthy = (v["index"] % 3) != 0  # каждый третий в демо «лежит», чтобы было видно статусы
        if v.get("deploy", {}).get("status") in ("never",) and v["index"] > 2:
            healthy = False
        wg[iface] = {"listen_port": None, "peers": [{
            "public_key": v["wg"]["home_pub" if store.home.get("mode") == "keenetic" else "vps_pub"], "endpoint": f"127.0.0.1:{v['local_port']}",
            "allowed_ips": "0.0.0.0/0", "latest_handshake": now - rnd.randint(5, 110) if healthy else 0,
            "rx": rnd.randint(10**6, 10**10) if healthy else 0, "tx": rnd.randint(10**6, 10**9) if healthy else 0}]}
        if healthy:
            ospf.append({"router_id": v["vps_router_id"], "state": "Full/PtP", "dead": "17.3", "iface": iface,
                         "ip": v["vps_tun_ip"]})
            routes.append({"net": f"{v['vps_tun_ip']}/31", "type": "unicast", "proto": "ospf1", "primary": True,
                           "via": None, "iface": iface, "metric": str(v["cost"])})
    services = {"xray": "active" if store.vps else "inactive", "bird": "active", "awg-quick@awg-home": "active"}
    return _assemble(store, wg, ospf, routes, devices, services, demo=True)
