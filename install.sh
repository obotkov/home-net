#!/usr/bin/env bash
# Установка / обновление netadmin одной командой:
#   curl -fsSL https://raw.githubusercontent.com/obotkov/home-net/main/install.sh | sudo bash
#
# Повторный запуск обновляет код, не трогая состояние и ключи (/var/lib/netadmin).
# Параметры через окружение (sudo -E или перед bash):
#   NETADMIN_REF=main            ветка или тег
#   NETADMIN_LISTEN=IP:PORT      адрес панели (по умолчанию LAN-адрес узла:8088)
#   NETADMIN_APPLY=1             кнопка «Применить дома» сразу применяет конфиг (по умолчанию 1)
#   NETADMIN_SKIP_DEPS=1         не ставить пакеты
#   NETADMIN_GITHUB_TOKEN=...    токен для приватного репозитория
# Удаление:  curl -fsSL .../install.sh | sudo bash -s -- --uninstall
set -euo pipefail

REPO="${NETADMIN_REPO:-obotkov/home-net}"
REF="${NETADMIN_REF:-main}"
PREFIX=/opt/netadmin
STATE_DIR=/var/lib/netadmin
ENV_FILE=/etc/netadmin.env
UNIT=/etc/systemd/system/netadmin.service

say() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mОшибка:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "запустите от root: curl ... | sudo bash"
command -v systemctl >/dev/null || die "нужен systemd"

if [ "${1:-}" = "--uninstall" ]; then
  say "удаляю netadmin (состояние в $STATE_DIR оставляю)"
  systemctl disable --now netadmin 2>/dev/null || true
  rm -rf "$PREFIX" "$UNIT"
  systemctl daemon-reload
  say "готово. Ключи и VPS остались в $STATE_DIR, пароль в $ENV_FILE"
  exit 0
fi

# ---------------------------------------------------------------- пакеты
if [ "${NETADMIN_SKIP_DEPS:-0}" != 1 ]; then
  say "ставлю зависимости"
  if command -v apt-get >/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq python3 wireguard-tools bird2 curl tar iproute2 openssh-client >/dev/null
  elif command -v dnf >/dev/null; then
    dnf install -y -q python3 wireguard-tools bird curl tar iproute openssh-clients
  elif command -v pacman >/dev/null; then
    pacman -Sy --noconfirm --needed python wireguard-tools bird curl tar iproute2 openssh
  else
    die "неизвестный пакетный менеджер; поставьте python3, wireguard-tools, bird2 и запустите с NETADMIN_SKIP_DEPS=1"
  fi
fi
command -v python3 >/dev/null || die "нет python3"
python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))' || die "нужен Python 3.9+"

# ---------------------------------------------------------------- код
say "скачиваю $REPO@$REF"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
if [ -n "${NETADMIN_GITHUB_TOKEN:-}" ]; then  # приватный репозиторий
  URL="https://api.github.com/repos/$REPO/tarball/$REF"; AUTH=(-H "Authorization: Bearer $NETADMIN_GITHUB_TOKEN")
else
  URL="https://codeload.github.com/$REPO/tar.gz/$REF"; AUTH=()
fi
curl -fsSL "${AUTH[@]}" "$URL" | tar -xz -C "$TMP" --strip-components=1 \
  || die "не удалось скачать https://github.com/$REPO (репозиторий приватный? см. README)"
[ -f "$TMP/netadmin/app.py" ] || die "в архиве нет netadmin/app.py"
rm -rf "$PREFIX.new"
mkdir -p "$PREFIX.new"
cp -r "$TMP/netadmin" "$PREFIX.new/"
cp "$TMP/install.sh" "$TMP/README.md" "$PREFIX.new/" 2>/dev/null || true
rm -rf "$PREFIX.old"
[ -d "$PREFIX" ] && mv "$PREFIX" "$PREFIX.old"
mv "$PREFIX.new" "$PREFIX"
rm -rf "$PREFIX.old"

# ---------------------------------------------------------------- настройки (только при первой установке)
install -d -m 700 "$STATE_DIR"
FIRST=0
if [ ! -f "$ENV_FILE" ]; then
  FIRST=1
  LAN_IF=$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); exit}}')
  LAN_IP=$(ip -4 -o addr show dev "${LAN_IF:-lo}" 2>/dev/null | awk '{print $4; exit}')
  LAN_CIDR=$(python3 -c "import ipaddress,sys; print(ipaddress.ip_interface(sys.argv[1]).network)" "${LAN_IP:-192.168.1.1/24}")
  LISTEN="${NETADMIN_LISTEN:-${LAN_IP%/*}:8088}"
  PASS=$(python3 -c 'import secrets; print(secrets.token_urlsafe(12))')
  umask 077
  cat > "$ENV_FILE" <<EOF
# netadmin — меняйте и делайте: systemctl restart netadmin
NETADMIN_PASSWORD=$PASS
NETADMIN_LISTEN=$LISTEN
NETADMIN_APPLY=${NETADMIN_APPLY:-1}
NETADMIN_STATE=$STATE_DIR/state.json
NETADMIN_OUT=$STATE_DIR/out
# значения по умолчанию для первого запуска (потом правятся в «Настройках»)
NETADMIN_LAN_IF=${LAN_IF:-br-lan}
NETADMIN_LAN_CIDR=$LAN_CIDR
NETADMIN_NAME=$(hostname -s 2>/dev/null | tr 'A-Z' 'a-z' | cut -c1-12 || echo home)
EOF
fi

# SSH-ключ для кнопки «Развернуть по SSH»
[ -f /root/.ssh/id_ed25519 ] || { install -d -m 700 /root/.ssh; ssh-keygen -q -t ed25519 -N '' -f /root/.ssh/id_ed25519 -C netadmin; }

# ---------------------------------------------------------------- systemd
cat > "$UNIT" <<EOF
[Unit]
Description=netadmin — админка домашней сети
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=$PREFIX
EnvironmentFile=$ENV_FILE
ExecStart=$(command -v python3) -m netadmin
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable -q netadmin
systemctl restart netadmin
sleep 1
systemctl is-active -q netadmin || { journalctl -u netadmin -n 30 --no-pager; die "сервис не запустился"; }

# ---------------------------------------------------------------- итог
. "$ENV_FILE"
echo
say "netadmin работает: http://$NETADMIN_LISTEN   логин: admin"
if [ "$FIRST" = 1 ]; then
  say "пароль: $NETADMIN_PASSWORD   (хранится в $ENV_FILE)"
  say "LAN: $NETADMIN_LAN_IF $NETADMIN_LAN_CIDR — проверьте во вкладке «Настройки»"
else
  say "код обновлён, состояние и пароль не тронуты"
fi
say "ключ для VPS (добавьте в ~/.ssh/authorized_keys на каждом VPS или: ssh-copy-id -i /root/.ssh/id_ed25519 root@VPS):"
cat /root/.ssh/id_ed25519.pub
