"""Генерация конфигов: WireGuard, Xray (VLESS+REALITY), BIRD/OSPF и скриптов установки."""
import json
import urllib.parse

MARK = "# managed-by netadmin"
VPS_WG_PORT = 51820
PRIVATE_SET = "[10.0.0.0/8+, 172.16.0.0/12+, 192.168.0.0/16+]"
XRAY_INSTALL = 'bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install'


def home_iface(v):
    return f"wg-{v['name']}"[:15]


# ---------------------------------------------------------------- WireGuard
def wg_home_conf(home, v):
    return f"""{MARK}
# Линк дом <-> {v['name']} ({v['public_ip']}), UDP идёт через локальный Xray
[Interface]
PrivateKey = {v['wg']['home_priv']}
Address = {v['home_tun_ip']}/31
MTU = {home['wg_mtu']}
Table = off

[Peer]
PublicKey = {v['wg']['vps_pub']}
PresharedKey = {v['wg']['psk']}
Endpoint = 127.0.0.1:{v['local_port']}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""


def wg_vps_conf(home, v):
    return f"""{MARK}
[Interface]
PrivateKey = {v['wg']['vps_priv']}
Address = {v['vps_tun_ip']}/31
ListenPort = {VPS_WG_PORT}
MTU = {home['wg_mtu']}
Table = off

[Peer]
PublicKey = {v['wg']['home_pub']}
PresharedKey = {v['wg']['psk']}
AllowedIPs = 0.0.0.0/0
"""


# ---------------------------------------------------------------- Xray
def _reality_stream(v, server):
    rs = {"serverName": v["sni"], "fingerprint": "chrome", "publicKey": v["xray"]["reality_pub"],
          "shortId": v["xray"]["short_id"]}
    if server:
        rs = {"show": False, "dest": f"{v['sni']}:443", "xver": 0, "serverNames": [v["sni"]],
              "privateKey": v["xray"]["reality_priv"], "shortIds": [v["xray"]["short_id"]]}
    return {"network": "tcp", "security": "reality", "realitySettings": rs}


def xray_home_conf(home, vps_list):
    """Клиент Xray дома: на каждый VPS свой локальный UDP-порт -> свой VLESS outbound."""
    inbounds, outbounds, rules = [], [], []
    for v in sorted(vps_list, key=lambda x: x["index"]):
        inbounds.append({
            "tag": f"in-{v['name']}", "listen": "127.0.0.1", "port": v["local_port"],
            "protocol": "dokodemo-door",
            "settings": {"address": "127.0.0.1", "port": VPS_WG_PORT, "network": "udp"},
        })
        outbounds.append({
            "tag": f"out-{v['name']}", "protocol": "vless",
            "settings": {"vnext": [{"address": v["public_ip"], "port": v["xray_port"], "users": [
                {"id": v["xray"]["link_uuid"], "encryption": "none", "flow": "xtls-rprx-vision"}]}]},
            "streamSettings": _reality_stream(v, server=False),
        })
        rules.append({"type": "field", "inboundTag": [f"in-{v['name']}"], "outboundTag": f"out-{v['name']}"})
    outbounds.append({"tag": "block", "protocol": "blackhole"})
    return json.dumps({
        "log": {"loglevel": "warning"},
        "policy": {"levels": {"0": {"connIdle": 600}}},
        "inbounds": inbounds,
        "outbounds": outbounds or [{"tag": "block", "protocol": "blackhole"}],
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }, indent=2, ensure_ascii=False)


def xray_vps_conf(home, v):
    """Сервер Xray на VPS. Линк дома ходит только на локальный WireGuard,
    клиенты (телефон/ноутбук) получают доступ к домашней сети и интернету через VPS."""
    return json.dumps({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "vless-in", "port": v["xray_port"], "protocol": "vless",
            "settings": {"decryption": "none", "clients": [
                {"id": v["xray"]["link_uuid"], "flow": "xtls-rprx-vision", "email": "link@home"},
                {"id": v["xray"]["client_uuid"], "flow": "xtls-rprx-vision", "email": f"client@{v['name']}"},
            ]},
            "streamSettings": _reality_stream(v, server=True),
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True},
        }],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}, {"tag": "block", "protocol": "blackhole"}],
        "routing": {"domainStrategy": "AsIs", "rules": [
            {"type": "field", "user": ["link@home"], "ip": ["127.0.0.1/32"], "port": str(VPS_WG_PORT),
             "network": "udp", "outboundTag": "direct"},
            {"type": "field", "user": ["link@home"], "outboundTag": "block"},
            {"type": "field", "ip": ["127.0.0.0/8", "::1/128"], "outboundTag": "block"},
        ]},
    }, indent=2, ensure_ascii=False)


def client_link(home, v):
    q = urllib.parse.urlencode({
        "encryption": "none", "flow": "xtls-rprx-vision", "security": "reality", "sni": v["sni"],
        "fp": "chrome", "pbk": v["xray"]["reality_pub"], "sid": v["xray"]["short_id"], "type": "tcp",
    })
    return f"vless://{v['xray']['client_uuid']}@{v['public_ip']}:{v['xray_port']}?{q}#{urllib.parse.quote(v['label'])}"


# ---------------------------------------------------------------- BIRD
def bird_home_conf(home, vps_list):
    ifaces = "\n".join(
        f'    interface "{home_iface(v)}" {{ type ptp; cost {v["cost"]}; hello 5; dead 20; }};'
        for v in sorted(vps_list, key=lambda x: x["index"]))
    return f"""{MARK}
log syslog all;
router id {home['router_id']};

define PRIVATE = {PRIVATE_SET};

protocol device {{ scan time 10; }}

# Ставим в ядро только то, что выучили по OSPF
protocol kernel {{
  ipv4 {{ import none; export where source = RTS_OSPF; }};
}}

protocol ospf v2 ospf1 {{
  # Принимаем только частные сети: default и публичные адреса VPS никогда не уйдут в туннель
  ipv4 {{ import where net ~ PRIVATE; export none; }};
  area 0 {{
    interface "{home['lan_if']}" {{ stub yes; }};
{ifaces}
    interface "wg-*" {{ type ptp; cost {home['ospf_cost']}; hello 5; dead 20; }};
  }};
}}
"""


def bird_vps_conf(home, v):
    return f"""{MARK}
log syslog all;
router id {v['vps_router_id']};

define PRIVATE = {PRIVATE_SET};

protocol device {{ scan time 10; }}

protocol kernel {{
  ipv4 {{ import none; export where source = RTS_OSPF; }};
}}

protocol ospf v2 ospf1 {{
  ipv4 {{ import where net ~ PRIVATE; export none; }};
  area 0 {{
    interface "wg-*" {{ type ptp; cost {v['cost']}; hello 5; dead 20; }};
  }};
}}
"""


# ---------------------------------------------------------------- scripts
def _heredoc(path, content, mode="600"):
    return f"install -d \"$(dirname {path})\"\ncat > {path} <<'NETADMIN_EOF'\n{content.rstrip()}\nNETADMIN_EOF\nchmod {mode} {path}\n"


_SYSCTL = """cat > /etc/sysctl.d/90-netadmin.conf <<'NETADMIN_EOF'
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
NETADMIN_EOF
sysctl --system >/dev/null
"""


def vps_bootstrap(home, v):
    """Скрипт для Debian/Ubuntu VPS. Запускается от root: ssh root@vps 'bash -s' < script."""
    return f"""#!/usr/bin/env bash
# netadmin: установка узла {v['name']} ({v['public_ip']})
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
[ "$(id -u)" = 0 ] || {{ echo "Нужен root"; exit 1; }}

echo "== пакеты"
apt-get update -qq
apt-get install -y -qq wireguard-tools bird2 nftables curl >/dev/null
command -v xray >/dev/null || {XRAY_INSTALL}

echo "== конфиги"
{_heredoc('/etc/wireguard/wg-home.conf', wg_vps_conf(home, v))}
{_heredoc('/usr/local/etc/xray/config.json', xray_vps_conf(home, v), '644')}
{_heredoc('/etc/bird/bird.conf', bird_vps_conf(home, v), '640')}
chown bird:bird /etc/bird/bird.conf 2>/dev/null || true
{_SYSCTL}
echo "== фаервол: WireGuard доступен только через локальный Xray"
{_heredoc('/etc/nftables.d/netadmin.nft', f'''table inet netadmin {{
  chain input {{
    type filter hook input priority -10; policy accept;
    udp dport {VPS_WG_PORT} iifname != "lo" drop
  }}
}}''', '644')}
nft delete table inet netadmin 2>/dev/null || true
nft -f /etc/nftables.d/netadmin.nft
grep -q netadmin.nft /etc/nftables.conf 2>/dev/null || echo 'include "/etc/nftables.d/netadmin.nft"' >> /etc/nftables.conf
systemctl enable -q nftables

echo "== сервисы"
systemctl enable -q wg-quick@wg-home
systemctl restart wg-quick@wg-home
systemctl enable -q xray && systemctl restart xray
systemctl enable -q bird && systemctl restart bird
sleep 2
wg show wg-home | head -n 5 || true
birdc -r show protocols || true
echo "== готово"
"""


def home_apply_script(home, vps_list):
    """Скрипт для домашнего узла: все линки, клиент Xray, BIRD. Удаляет линки удалённых VPS."""
    names = " ".join(home_iface(v) for v in vps_list)
    parts = [f"""#!/usr/bin/env bash
# netadmin: применение конфигурации домашнего узла
set -euo pipefail
[ "$(id -u)" = 0 ] || {{ echo "Нужен root"; exit 1; }}
command -v wg >/dev/null || {{ echo "Установите wireguard-tools и bird2"; exit 1; }}
command -v xray >/dev/null || {XRAY_INSTALL}
"""]
    for v in vps_list:
        parts.append(_heredoc(f"/etc/wireguard/{home_iface(v)}.conf", wg_home_conf(home, v)))
    parts.append(_heredoc("/usr/local/etc/xray/config.json", xray_home_conf(home, vps_list), "644"))
    parts.append(_heredoc("/etc/bird/bird.conf", bird_home_conf(home, vps_list), "640"))
    parts.append("chown bird:bird /etc/bird/bird.conf 2>/dev/null || true\n")
    parts.append(_SYSCTL)
    # NAT из туннелей в LAN: домашним компам не нужен обратный маршрут к 10.255.x.x
    # (их шлюз — обычный роутер), и Windows-фаервол видит соединение как локальное.
    parts.append(_heredoc("/etc/nftables.d/netadmin-home.nft", f"""table ip netadmin_home {{
  chain postrouting {{
    type nat hook postrouting priority srcnat; policy accept;
    oifname "{home['lan_if']}" ip saddr {home['transit_pool']} masquerade
  }}
}}""", "644"))
    parts.append("""command -v nft >/dev/null || { apt-get install -y -qq nftables >/dev/null 2>&1 || true; }
nft delete table ip netadmin_home 2>/dev/null || true
nft -f /etc/nftables.d/netadmin-home.nft
[ -f /etc/nftables.conf ] && ! grep -q netadmin-home.nft /etc/nftables.conf && echo 'include "/etc/nftables.d/netadmin-home.nft"' >> /etc/nftables.conf
systemctl enable -q nftables 2>/dev/null || true
""")
    parts.append(f"""
KEEP=" {names} "
for f in /etc/wireguard/wg-*.conf; do
  [ -e "$f" ] || continue
  grep -q '{MARK}' "$f" || continue
  i=$(basename "$f" .conf)
  case "$KEEP" in *" $i "*) ;; *)
    echo "удаляю старый линк $i"
    systemctl disable --now -q "wg-quick@$i" || true
    rm -f "$f" ;;
  esac
done
systemctl enable -q xray && systemctl restart xray
for i in $KEEP; do systemctl enable -q "wg-quick@$i"; systemctl restart "wg-quick@$i"; done
systemctl restart bird 2>/dev/null || systemctl restart bird2
echo "готово"
""")
    return "\n".join(parts)


# ---------------------------------------------------------------- режим Keenetic (AmneziaWG)
def _asc_lines(a):
    return (f"Jc = {a['jc']}\nJmin = {a['jmin']}\nJmax = {a['jmax']}\nS1 = {a['s1']}\nS2 = {a['s2']}\n"
            f"H1 = {a['h1']}\nH2 = {a['h2']}\nH3 = {a['h3']}\nH4 = {a['h4']}")


def awg_vps_conf(home, v):
    a = v["awg"]
    return f"""{MARK}
# Линк VPS {v['name']} <-> Keenetic (AmneziaWG). Домашняя сеть {home['lan_cidr']} маршрутизируется в туннель.
[Interface]
PrivateKey = {v['wg']['vps_priv']}
Address = {v['vps_tun_ip']}/31
ListenPort = {a['port']}
MTU = {home['wg_mtu']}
{_asc_lines(a)}

[Peer]
PublicKey = {v['wg']['home_pub']}
PresharedKey = {v['wg']['psk']}
AllowedIPs = {v['home_tun_ip']}/32, {home['lan_cidr']}
"""


def keenetic_conf(home, v):
    """Файл для импорта в Keenetic: «Интернет → Другие подключения → WireGuard → Загрузить из файла»."""
    a = v["awg"]
    return f"""[Interface]
PrivateKey = {v['wg']['home_priv']}
Address = {v['home_tun_ip']}/31
MTU = {home['wg_mtu']}
{_asc_lines(a)}

[Peer]
PublicKey = {v['wg']['vps_pub']}
PresharedKey = {v['wg']['psk']}
Endpoint = {v['public_ip']}:{a['port']}
AllowedIPs = {v['vps_tun_ip']}/32
PersistentKeepalive = 25
"""


def keenetic_cli(home, v, iface="Wireguard0"):
    """Команды CLI Keenetic после импорта: доступ из туннеля в домашнюю сеть и проверка ASC."""
    a = v["awg"]
    return f"""interface {iface} security-level private
interface {iface} wireguard asc {a['jc']} {a['jmin']} {a['jmax']} {a['s1']} {a['s2']} {a['h1']} {a['h2']} {a['h3']} {a['h4']}
interface {iface} up
system configuration save
show interface {iface}
"""


def vps_bootstrap_keenetic(home, v):
    """VPS для режима Keenetic: сервер AmneziaWG до роутера + Xray для телефонов."""
    a = v["awg"]
    return f"""#!/usr/bin/env bash
# netadmin (режим Keenetic): установка узла {v['name']} ({v['public_ip']})
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
[ "$(id -u)" = 0 ] || {{ echo "Нужен root"; exit 1; }}

echo "== пакеты"
apt-get update -qq
apt-get install -y -qq curl gnupg nftables "linux-headers-$(uname -r)" >/dev/null || \
  apt-get install -y -qq curl gnupg nftables >/dev/null
command -v xray >/dev/null || {{ echo "-- установка Xray"; {XRAY_INSTALL} >/dev/null; }}

echo "== AmneziaWG"
. /etc/os-release
if [ ! -f /etc/apt/sources.list.d/amnezia.list ]; then
  CODENAME=focal; [ "$ID" = ubuntu ] && CODENAME="$VERSION_CODENAME"
  FPR=$(curl -fsSL https://api.launchpad.net/1.0/~amnezia/+archive/ubuntu/ppa \\
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["signing_key_fingerprint"])')
  curl -fsSL "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x$FPR" | gpg --dearmor --yes -o /usr/share/keyrings/amnezia.gpg
  echo "deb [signed-by=/usr/share/keyrings/amnezia.gpg] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu $CODENAME main" \\
    > /etc/apt/sources.list.d/amnezia.list
  apt-get update -qq
fi
# если прошлый запуск оставил недособранный модуль, убираем его, чтобы apt не падал
ST=$(dpkg-query -W -f='${{Status}}' amneziawg-dkms 2>/dev/null || true)
if [ -n "$ST" ] && [ "$ST" != "install ok installed" ] && [ "$ST" != "unknown ok not-installed" ]; then
  apt-get purge -y -qq amneziawg amneziawg-dkms >/dev/null 2>&1 || dpkg --purge --force-all amneziawg amneziawg-dkms >/dev/null 2>&1 || true
fi
dpkg --configure -a >/dev/null 2>&1 || true
apt-get install -y -qq amneziawg-tools >/dev/null
if ! modprobe amneziawg 2>/dev/null; then
  echo "-- пробую модуль ядра (DKMS)"
  if apt-get install -y -qq amneziawg-dkms >/dev/null 2>/tmp/awg-dkms.err && modprobe amneziawg 2>/dev/null; then
    echo "   модуль ядра собран"
  else
    echo "   модуль ядра для $(uname -r) не собрался, ставлю amneziawg-go (без модуля ядра)"
    tail -n 5 /tmp/awg-dkms.err 2>/dev/null || true
    apt-get purge -y -qq amneziawg amneziawg-dkms >/dev/null 2>&1 || dpkg --purge --force-all amneziawg amneziawg-dkms >/dev/null 2>&1 || true
    dpkg --configure -a >/dev/null 2>&1 || true
  fi
fi
if ! lsmod | grep -q '^amneziawg' && ! command -v amneziawg-go >/dev/null; then
  [ -c /dev/net/tun ] || {{ echo "Нет /dev/net/tun: включите TUN/TAP в панели хостера (OpenVZ/LXC) и повторите"; exit 1; }}
  echo "-- сборка amneziawg-go"
  apt-get install -y -qq git make >/dev/null
  GOARCH=$(dpkg --print-architecture)
  GOVER=$(curl -fsSL 'https://go.dev/dl/?mode=json' | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["version"])')
  rm -rf /opt/netadmin-go && mkdir -p /opt/netadmin-go
  curl -fsSL "https://go.dev/dl/$GOVER.linux-$GOARCH.tar.gz" | tar -C /opt/netadmin-go -xz
  rm -rf /tmp/amneziawg-go
  git clone -q --depth 1 https://github.com/amnezia-vpn/amneziawg-go /tmp/amneziawg-go
  (cd /tmp/amneziawg-go && PATH="/opt/netadmin-go/go/bin:$PATH" GOTOOLCHAIN=auto make >/dev/null)
  install -m 755 /tmp/amneziawg-go/amneziawg-go /usr/local/bin/amneziawg-go
  rm -rf /tmp/amneziawg-go /opt/netadmin-go
  echo "   amneziawg-go установлен"
fi
if ! lsmod | grep -q '^amneziawg'; then
  install -d /etc/systemd/system/awg-quick@.service.d
  printf '[Service]\\nEnvironment=WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go\\n' \\
    > /etc/systemd/system/awg-quick@.service.d/userspace.conf
  systemctl daemon-reload
fi

echo "== конфиги"
{_heredoc('/etc/amnezia/amneziawg/awg-home.conf', awg_vps_conf(home, v))}
{_heredoc('/usr/local/etc/xray/config.json', xray_vps_conf(home, v), '644')}
{_SYSCTL}
if command -v ufw >/dev/null && ufw status | grep -q '^Status: active'; then ufw allow {a['port']}/udp >/dev/null; ufw allow {v['xray_port']}/tcp >/dev/null; fi

echo "== сервисы"
systemctl enable -q awg-quick@awg-home
systemctl restart awg-quick@awg-home
systemctl enable -q xray && systemctl restart xray
sleep 1
awg show awg-home | head -n 8 || true
echo "== готово. Теперь импортируйте конфиг в Keenetic (кнопка «Конфиг для Keenetic» в панели)"
"""


def bootstrap_for(home, v):
    return vps_bootstrap_keenetic(home, v) if home.get("mode") == "keenetic" else vps_bootstrap(home, v)


def all_files(home, vps_list, v=None):
    """Набор файлов для скачивания: для VPS или для дома."""
    if v and home.get("mode") == "keenetic":
        return {
            f"{v['name']}/keenetic-{v['name']}.conf": keenetic_conf(home, v),
            f"{v['name']}/keenetic-cli.txt": keenetic_cli(home, v),
            f"{v['name']}/bootstrap.sh": vps_bootstrap_keenetic(home, v),
            f"{v['name']}/awg-home.conf": awg_vps_conf(home, v),
            f"{v['name']}/xray.json": xray_vps_conf(home, v),
            f"{v['name']}/client-link.txt": client_link(home, v) + "\n",
        }
    if v:
        return {
            f"{v['name']}/bootstrap.sh": vps_bootstrap(home, v),
            f"{v['name']}/wg-home.conf": wg_vps_conf(home, v),
            f"{v['name']}/xray.json": xray_vps_conf(home, v),
            f"{v['name']}/bird.conf": bird_vps_conf(home, v),
            f"{v['name']}/client-link.txt": client_link(home, v) + "\n",
        }
    files = {"home/apply.sh": home_apply_script(home, vps_list),
             "home/xray.json": xray_home_conf(home, vps_list),
             "home/bird.conf": bird_home_conf(home, vps_list)}
    for x in vps_list:
        files[f"home/{home_iface(x)}.conf"] = wg_home_conf(home, x)
    return files
