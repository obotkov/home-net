"""Хранилище состояния: один JSON-файл с правами 600 (внутри приватные ключи)."""
import ipaddress
import json
import os
import re
import secrets
import threading
import time

from . import keys

_LOCK = threading.Lock()

DEFAULT_HOME = {
    "name": "home",
    "lan_if": "br-lan",
    "lan_cidr": "192.168.1.0/24",
    "transit_pool": "10.255.0.0/24",  # /31 на каждый линк дом <-> VPS
    "router_id_pool": "10.254.0.0/24",  # router id: дом .1, VPS .2, .3 ...
    "xray_local_base": 20000,  # локальные UDP-порты dokodemo-door: 20001, 20002 ...
    "wg_mtu": 1280,
    "ospf_cost": 10,
    # linux    — дома Linux-узел с панелью: Xray-линки + WireGuard + BIRD/OSPF
    # keenetic — панель на VPS, дома роутер Keenetic: AmneziaWG (WireGuard с обфускацией ASC) до каждого VPS
    "mode": "linux",
    "keenetic_lan_if": "Bridge0",
}

SLUG_RE = re.compile(r"^[a-z][a-z0-9-]{0,11}$")


class Store:
    def __init__(self, path):
        self.path = path
        home = dict(DEFAULT_HOME)
        # начальные значения при первом запуске (их подставляет install.sh)
        for key, env in (("lan_if", "NETADMIN_LAN_IF"), ("lan_cidr", "NETADMIN_LAN_CIDR"), ("name", "NETADMIN_NAME")):
            if os.environ.get(env):
                home[key] = os.environ[env]
        self.data = {"home": home, "vps": []}
        if os.path.exists(path):
            with open(path) as f:
                loaded = json.load(f)
            self.data["home"].update(loaded.get("home", {}))
            self.data["vps"] = loaded.get("vps", [])
            self.data["passkeys"] = loaded.get("passkeys", [])
        self._ensure_home_keys()
        changed = False
        for v in self.data["vps"]:
            changed |= ensure_awg(v)
        if changed and os.path.exists(path):
            self.save()

    # -------- persistence
    def save(self):
        tmp = self.path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(self.data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, self.path)

    def _ensure_home_keys(self):
        if "router_id" not in self.data["home"]:
            pool = ipaddress.ip_network(self.data["home"]["router_id_pool"])
            self.data["home"]["router_id"] = str(pool.network_address + 1)

    @property
    def home(self):
        return self.data["home"]

    @property
    def vps(self):
        return self.data["vps"]

    def get_vps(self, vid):
        return next((v for v in self.vps if v["id"] == vid), None)

    # -------- address plan
    def _next_index(self):
        used = {v["index"] for v in self.vps}
        i = 1
        while i in used:
            i += 1
        return i

    def plan_for(self, index):
        h = self.home
        transit = ipaddress.ip_network(h["transit_pool"])
        base = transit.network_address + 2 * (index - 1)
        if base + 1 not in transit:
            raise ValueError("Закончились адреса в transit_pool")
        rid_pool = ipaddress.ip_network(h["router_id_pool"])
        return {
            "vps_tun_ip": str(base),
            "home_tun_ip": str(base + 1),
            "vps_router_id": str(rid_pool.network_address + 1 + index),
            "local_port": h["xray_local_base"] + index,
        }

    # -------- CRUD
    def add_vps(self, form):
        name = (form.get("name") or "").strip().lower()
        if not SLUG_RE.match(name):
            raise ValueError("Имя: латиница, цифры, дефис, до 12 символов, начинается с буквы")
        if any(v["name"] == name for v in self.vps):
            raise ValueError("VPS с таким именем уже есть")
        ip = (form.get("public_ip") or "").strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise ValueError("Некорректный публичный IP")
        with _LOCK:
            idx = self._next_index()
            vps_wg_priv, vps_wg_pub = keys.wg_keypair()
            home_wg_priv, home_wg_pub = keys.wg_keypair()
            r_priv, r_pub = keys.reality_keypair()
            v = {
                "id": keys.short_id(),
                "index": idx,
                "name": name,
                "label": (form.get("label") or "").strip() or name,
                "public_ip": ip,
                "ssh_user": (form.get("ssh_user") or "root").strip(),
                "ssh_port": int(form.get("ssh_port") or 22),
                "xray_port": int(form.get("xray_port") or 443),
                "sni": (form.get("sni") or "www.microsoft.com").strip(),
                "cost": int(form.get("cost") or self.home["ospf_cost"]),
                "wg": {
                    "vps_priv": vps_wg_priv, "vps_pub": vps_wg_pub,
                    "home_priv": home_wg_priv, "home_pub": home_wg_pub,
                    "psk": keys.wg_psk(),
                },
                "xray": {
                    "link_uuid": keys.new_uuid(),   # туннель дом -> VPS
                    "client_uuid": keys.new_uuid(),  # телефоны / ноутбуки
                    "reality_priv": r_priv, "reality_pub": r_pub,
                    "short_id": keys.short_id(),
                },
                "created": int(time.time()),
                "deploy": {"status": "never", "log": "", "at": None},
                **self.plan_for(idx),
            }
            ensure_awg(v)
            self.vps.append(v)
            self.save()
        return v

    def update_vps(self, vid, form):
        v = self.get_vps(vid)
        if not v:
            raise KeyError(vid)
        for key in ("label", "sni", "ssh_user"):
            if key in form:
                v[key] = str(form[key]).strip()
        for key in ("ssh_port", "xray_port", "cost"):
            if key in form:
                v[key] = int(form[key])
        self.save()
        return v

    def delete_vps(self, vid):
        with _LOCK:
            before = len(self.vps)
            self.data["vps"] = [v for v in self.vps if v["id"] != vid]
            if len(self.vps) == before:
                raise KeyError(vid)
            self.save()

    def update_home(self, form):
        allowed = {"name", "lan_if", "lan_cidr", "wg_mtu", "ospf_cost", "mode"}
        if "mode" in form and form["mode"] not in ("linux", "keenetic"):
            raise ValueError("режим: linux или keenetic")
        for k, val in form.items():
            if k in allowed:
                self.home[k] = int(val) if k in ("wg_mtu", "ospf_cost") else str(val).strip()
        ipaddress.ip_network(self.home["lan_cidr"])
        self.save()
        return self.home


def ensure_awg(v):
    """Параметры AmneziaWG (ASC) для линка: одинаковые на VPS и на Keenetic. Возвращает True, если добавлены."""
    if "awg" in v:
        return False
    r = secrets.SystemRandom()
    s1 = r.randint(15, 150)
    s2 = r.randint(15, 150)
    while s1 + 56 == s2:
        s2 = r.randint(15, 150)
    hs = set()
    while len(hs) < 4:
        hs.add(r.randint(5, 2**31 - 1))
    h1, h2, h3, h4 = sorted(hs)
    v["awg"] = {"port": r.randint(40000, 59999), "jc": r.randint(4, 8), "jmin": 40, "jmax": 70,
                "s1": s1, "s2": s2, "h1": h1, "h2": h2, "h3": h3, "h4": h4}
    return True
