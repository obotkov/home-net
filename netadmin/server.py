"""Состояние служб на сервере, где запущена панель: Xray, WireGuard / AmneziaWG, BIRD.

Только чтение, кроме restart(). Секреты (приватные ключи, UUID клиентов) в ответ не попадают.
"""
import json
import os
import random
import re
import shutil
import subprocess
import time

from .collectors import demo_mode, parse_wg_dump

XRAY_CONF = "/usr/local/etc/xray/config.json"
AWG_DIR = "/etc/amnezia/amneziawg"
WG_DIR = "/etc/wireguard"
SECRET_KEYS = {"privatekey", "presharedkey", "id", "password", "privatekeyfile"}


def _run(cmd, timeout=6):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout
    except (OSError, subprocess.TimeoutExpired):
        return 1, ""


# ---------------------------------------------------------------- systemd
def _units():
    units = ["xray"]
    _, out = _run(["systemctl", "list-units", "--all", "--no-legend", "--plain", "--type=service",
                   "awg-quick@*", "wg-quick@*"])
    for line in out.splitlines():
        name = line.split()[0] if line.split() else ""
        if name.endswith(".service"):
            units.append(name[:-8])
    if shutil.which("bird"):
        units.append("bird")
    return list(dict.fromkeys(units))


def _unit_info(unit):
    props = "ActiveState,SubState,ActiveEnterTimestamp,MainPID,MemoryCurrent,NRestarts,LoadState,Result"
    _, out = _run(["systemctl", "show", unit, "-p", props])
    d = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    since = None
    ts = d.get("ActiveEnterTimestamp", "")
    if ts:
        _, epoch = _run(["date", "-d", ts, "+%s"])
        since = int(epoch.strip()) if epoch.strip().isdigit() else None
    mem = d.get("MemoryCurrent", "")
    _, log = _run(["journalctl", "-u", unit, "-n", "40", "--no-pager", "-o", "short-iso"])
    return {
        "unit": unit, "loaded": d.get("LoadState") == "loaded",
        "active": d.get("ActiveState", "unknown"), "sub": d.get("SubState", ""),
        "since": since, "pid": int(d.get("MainPID") or 0), "result": d.get("Result", ""),
        "memory": int(mem) if mem.isdigit() else None, "restarts": int(d.get("NRestarts") or 0),
        "log": log[-8000:],
    }


# ---------------------------------------------------------------- xray
def _mask(obj):
    """Копия конфига без секретов."""
    if isinstance(obj, dict):
        return {k: ("•••" if k.lower() in SECRET_KEYS and isinstance(v, str) else _mask(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_mask(x) for x in obj]
    return obj


def xray_summary(conf, listening=()):
    inbounds = []
    for ib in conf.get("inbounds", []):
        st = ib.get("streamSettings", {}) or {}
        rs = st.get("realitySettings", {}) or {}
        clients = (ib.get("settings", {}) or {}).get("clients", []) or []
        inbounds.append({
            "tag": ib.get("tag", ""), "listen": ib.get("listen", "0.0.0.0"), "port": ib.get("port"),
            "protocol": ib.get("protocol"), "network": st.get("network", "tcp"), "security": st.get("security", "none"),
            "sni": rs.get("serverNames", []), "dest": rs.get("dest") or rs.get("target"),
            "flow": sorted({c.get("flow", "") for c in clients if c.get("flow")}),
            "clients": [c.get("email") or "без имени" for c in clients],
            "listening": ib.get("port") in listening,
        })
    return {
        "inbounds": inbounds,
        "outbounds": [{"tag": o.get("tag", ""), "protocol": o.get("protocol")} for o in conf.get("outbounds", [])],
        "rules": len((conf.get("routing", {}) or {}).get("rules", [])),
        "loglevel": (conf.get("log", {}) or {}).get("loglevel", ""),
    }


def _listening_tcp():
    _, out = _run(["ss", "-Hltn"])
    ports = set()
    for line in out.splitlines():
        f = line.split()
        if len(f) > 3 and f[3].rsplit(":", 1)[-1].isdigit():
            ports.add(int(f[3].rsplit(":", 1)[-1]))
    return ports


def _xray():
    res = {"installed": bool(shutil.which("xray")), "version": None, "config_path": XRAY_CONF,
           "config": None, "summary": None, "error": None}
    if res["installed"]:
        _, out = _run(["xray", "version"])
        res["version"] = out.splitlines()[0] if out else None
    try:
        with open(XRAY_CONF) as f:
            conf = json.load(f)
        res["summary"] = xray_summary(conf, _listening_tcp())
        res["config"] = json.dumps(_mask(conf), indent=2, ensure_ascii=False)
    except FileNotFoundError:
        res["error"] = "конфиг не найден"
    except (OSError, ValueError) as e:
        res["error"] = f"конфиг не читается: {e}"
    return res


# ---------------------------------------------------------------- wireguard / amneziawg
ASC_KEYS = ("Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4")


def parse_conf_meta(text):
    """Несекретные поля [Interface] из wg/awg конфига: адрес, MTU, порт, ASC."""
    meta, section = {}, None
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line.startswith("["):
            section = line.strip("[]").lower()
            continue
        if section == "interface" and "=" in line:
            k, v = (x.strip() for x in line.split("=", 1))
            if k.lower() not in SECRET_KEYS:
                meta[k] = v
    return meta


def _tunnels():
    dumps = {}
    for tool in ("awg", "wg"):
        if shutil.which(tool):
            _, out = _run([tool, "show", "all", "dump"])
            for iface, d in parse_wg_dump(out).items():
                d["tool"] = tool
                dumps.setdefault(iface, d)
    _, pub = _run(["sh", "-c", "for i in $( (awg show interfaces; wg show interfaces) 2>/dev/null ); do "
                               "printf '%s ' $i; (awg show $i public-key || wg show $i public-key) 2>/dev/null; done"])
    pubs = dict(line.split()[:2] for line in pub.splitlines() if len(line.split()) >= 2)
    kernel_awg = os.path.exists("/sys/module/amneziawg")
    now = int(time.time())
    res = []
    for iface, d in sorted(dumps.items()):
        conf_path = os.path.join(AWG_DIR if d["tool"] == "awg" else WG_DIR, iface + ".conf")
        meta = {}
        try:
            with open(conf_path) as f:
                meta = parse_conf_meta(f.read())
        except OSError:
            pass
        res.append({
            "iface": iface, "tool": d["tool"], "listen_port": d["listen_port"], "public_key": pubs.get(iface),
            "impl": ("модуль ядра" if kernel_awg else "amneziawg-go") if d["tool"] == "awg" else "модуль ядра",
            "address": meta.get("Address"), "mtu": meta.get("MTU"), "conf_path": conf_path,
            "asc": {k: meta[k] for k in ASC_KEYS if k in meta},
            "peers": [{**p, "handshake_ago": (now - p["latest_handshake"]) if p["latest_handshake"] else None}
                      for p in d["peers"]],
        })
    return res


# ---------------------------------------------------------------- api
def status(store):
    if demo_mode():
        return _demo(store)
    return {"demo": False, "time": int(time.time()), "services": [_unit_info(u) for u in _units()],
            "xray": _xray(), "tunnels": _tunnels()}


def _free_port():
    import socket
    with socket.socket() as sk:
        sk.bind(("127.0.0.1", 0))
        return sk.getsockname()[1]


def xray_selftest(v, gw):
    """Подключаемся к своему Xray как телефон: VLESS+REALITY на публичный IP:порт, через него HTTP."""
    import tempfile
    steps = []
    code, text = _run(["curl", "-m", "6", "-s", "-o", "/dev/null", "-w", "HTTP %{http_code}\n", f"https://{v['sni']}"], 10)
    steps.append({"title": f"сайт маскировки {v['sni']} доступен с VPS", "ok": code == 0 and "000" not in text,
                  "output": text.strip()})
    port = _free_port()
    conf = {"log": {"loglevel": "warning"},
            "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": {"udp": False}}],
            "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": v["public_ip"], "port": v["xray_port"],
                           "users": [{"id": v["xray"]["client_uuid"], "flow": "xtls-rprx-vision", "encryption": "none"}]}]},
                           "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
                               "serverName": v["sni"], "fingerprint": "chrome", "publicKey": v["xray"]["reality_pub"],
                               "shortId": v["xray"]["short_id"]}}}]}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(conf, f)
        path = f.name
    os.chmod(path, 0o600)
    proc = None
    try:
        proc = subprocess.Popen(["xray", "run", "-c", path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        time.sleep(1.5)
        for title, url in ((f"телефонный путь: VPS {v['public_ip']}:{v['xray_port']} → интернет", "https://ifconfig.me/ip"),
                           (f"телефонный путь: VPS → дом http://{gw}", f"http://{gw}")):
            code, text = _run(["curl", "-m", "8", "-s", "-o", "/dev/null", "-w", "HTTP %{http_code}\n",
                               "--socks5-hostname", f"127.0.0.1:{port}", url], 12)
            steps.append({"title": title, "ok": code == 0 and "000" not in text, "output": text.strip()})
    finally:
        if proc:
            proc.terminate()
            try:
                log = proc.communicate(timeout=3)[0]
            except subprocess.TimeoutExpired:
                proc.kill()
                log = ""
            if not all(st["ok"] for st in steps[1:]) and log.strip():
                steps.append({"title": "журнал тестового клиента Xray", "ok": False, "output": log.strip()[-1500:]})
        os.unlink(path)
    return steps


def diagnose(store):
    """Проверка цепочки VPS -> туннель -> дом прямо с сервера панели."""
    home = store.home
    v = next((x for x in store.vps if x.get("local")), None)
    peer_ip = v["home_tun_ip"] if v else None
    gw = home["lan_cidr"].split("/")[0].rsplit(".", 1)[0] + ".1"
    steps = []
    if peer_ip:
        steps.append((f"ping {peer_ip} (роутер в туннеле)", ["ping", "-c", "3", "-W", "2", peer_ip]))
    steps += [
        (f"маршрут до {gw}", ["ip", "route", "get", gw]),
        (f"ping {gw} (роутер в домашней сети)", ["ping", "-c", "3", "-W", "2", gw]),
        (f"HTTP http://{gw}", ["curl", "-m", "5", "-s", "-o", "/dev/null", "-w", "HTTP %{http_code}\n", f"http://{gw}"]),
    ]
    out, ok_all = [], True
    for title, cmd in steps:
        if demo_mode():
            code, text = 0, "[демо] ok\n"
        else:
            code, text = _run(cmd, timeout=15)
            if cmd[0] == "curl" and text.strip() == "HTTP 000":
                code = 1
        ok_all &= code == 0
        out.append({"title": title, "ok": code == 0, "output": text.strip()[-1500:]})
    v_local = v
    xr = []
    if v_local and not demo_mode() and shutil.which("xray"):
        xr = xray_selftest(v_local, gw)
        out += xr
        ok_all &= all(st["ok"] for st in xr)
    hint = None
    by = {o["title"].split(" ")[0] + ("-tun" if "туннеле" in o["title"] else ""): o for o in out}
    route = next(o for o in out if o["title"].startswith("маршрут"))
    if not demo_mode() and not re.search(r"dev (awg|wg)", route["output"]):
        ok_all = False
        route["ok"] = False
        hint = (f"Маршрут в домашнюю сеть {home['lan_cidr']} идёт не через туннель. Проверьте LAN-подсеть в Настройках "
                "и нажмите «Переустановить» на карточке этого сервера.")
    elif not all(o["ok"] for o in out if o["title"].startswith("ping")):
        hint = ("Туннель до роутера поднят, но Keenetic не пускает трафик из него. В командной строке Keenetic "
                "(192.168.1.1/webcli/ или telnet 192.168.1.1) выполните «interface Wireguard0 security-level private», затем "
                "«system configuration save» (имя подключения может быть Wireguard1, видно в «show interface»).")
    elif not by.get("HTTP", {"ok": True})["ok"]:
        hint = "Роутер отвечает на ping, но веб-страница не открылась: проверьте доступ к веб-интерфейсу в настройках Keenetic."
    if hint is None and xr and not all(st["ok"] for st in xr):
        if not xr[0]["ok"]:
            hint = (f"VPS не может открыть сайт маскировки {v_local['sni']}: REALITY не будет работать. "
                    "Поменяйте SNI (например www.apple.com или dl.google.com) и переустановите сервер.")
        else:
            hint = ("Xray на VPS не принимает подключение даже от самого VPS: посмотрите журнал службы xray на этой вкладке "
                    "и нажмите «Переустановить» на карточке сервера.")
    elif hint is None and xr:
        hint = (f"С VPS всё работает, в том числе путь как у телефона. Если телефон не подключается: откройте у хостера "
                f"TCP-порт {v_local['xray_port']}, переимпортируйте ссылку и отключите в клиенте обход LAN.")
    return {"ok": ok_all, "steps": out, "hint": hint}


def restart(unit):
    if unit not in _units() and not demo_mode():
        raise ValueError("неизвестная служба")
    if demo_mode():
        return {"ok": True, "output": f"[демо] systemctl restart {unit}"}
    code, out = _run(["systemctl", "restart", unit], timeout=60)
    if code != 0:
        _, out = _run(["journalctl", "-u", unit, "-n", "15", "--no-pager", "-o", "cat"])
        raise ValueError(f"{unit} не перезапустился:\n{out[-1500:]}")
    return {"ok": True}


def _demo(store):
    from . import generator
    rnd = random.Random(7)
    now = int(time.time())
    vps = next((v for v in store.vps if v.get("local")), store.vps[0] if store.vps else None)
    keen = store.home.get("mode") == "keenetic"
    units = ["xray", "awg-quick@awg-home"] if keen else ["xray"] + [f"wg-quick@wg-{v['name']}" for v in store.vps] + ["bird"]
    services = [{"unit": u, "loaded": True, "active": "active", "sub": "running" if u in ("xray", "bird") else "exited",
                 "since": now - rnd.randint(600, 90000), "pid": rnd.randint(300, 9000) if u in ("xray", "bird") else 0,
                 "result": "success", "memory": rnd.randint(12, 60) * 2**20 if u in ("xray", "bird") else None,
                 "restarts": 0,
                 "log": f"2026-11-13T23:50:0{i}+03:00 vps {u}[123]: демо-строка журнала {i}\n" * 1}
                for i, u in enumerate(units)]
    xr = {"installed": True, "version": "Xray 26.11.9 (Xray, Penetrates Everything.)", "config_path": XRAY_CONF,
          "config": None, "summary": None, "error": None}
    tunnels = []
    if vps:
        conf = json.loads(generator.xray_vps_conf(store.home, vps))
        xr["summary"] = xray_summary(conf, {vps["xray_port"]})
        xr["config"] = json.dumps(_mask(conf), indent=2, ensure_ascii=False)
        if keen:
            a = vps["awg"]
            tunnels.append({
                "iface": "awg-home", "tool": "awg", "listen_port": a["port"], "public_key": vps["wg"]["vps_pub"],
                "impl": "amneziawg-go", "address": f"{vps['vps_tun_ip']}/31", "mtu": str(store.home["wg_mtu"]),
                "conf_path": f"{AWG_DIR}/awg-home.conf",
                "asc": {k: str(a[k.lower()]) for k in ASC_KEYS},
                "peers": [{"public_key": vps["wg"]["home_pub"], "endpoint": "95.24.17.203:41230",
                           "allowed_ips": f"{vps['home_tun_ip']}/32,{store.home['lan_cidr']}",
                           "latest_handshake": now - 37, "handshake_ago": 37,
                           "rx": rnd.randint(10**7, 10**9), "tx": rnd.randint(10**7, 10**9)}],
            })
    return {"demo": True, "time": now, "services": services, "xray": xr, "tunnels": tunnels}
