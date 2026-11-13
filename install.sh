#!/usr/bin/env bash
# Установка / обновление netadmin одной командой:
#   curl -fsSL https://raw.githubusercontent.com/obotkov/home-net/main/install.sh | sudo bash
#
# С доменом и сертификатом Let's Encrypt (Caddy получает и сам продлевает его):
#   curl -fsSL .../install.sh | sudo bash -s -- --domain panel.example.com --email me@example.com
#   ... --acme cloudflare --cf-token <API-токен>     # DNS-01: не нужен белый IP и открытые порты
#
# Повторный запуск обновляет код, не трогая состояние и ключи (/var/lib/netadmin).
# Параметры (флагом или переменной окружения):
#   --domain    NETADMIN_DOMAIN     домен панели; без него панель работает по http://IP:8088
#   --email     NETADMIN_EMAIL      почта для Let's Encrypt (уведомления об истечении)
#   --acme      NETADMIN_ACME       http (по умолчанию, нужны порты 80/443 из интернета) | cloudflare
#   --cf-token  NETADMIN_CF_TOKEN   токен Cloudflare с правом Zone:DNS:Edit (для --acme cloudflare)
#   --allow     NETADMIN_ALLOW      кому открыта панель по домену: "private" (LAN/VPN, по умолчанию) | "any" | список CIDR
#   --no-domain                     убрать домен и вернуться к http://IP:8088
#               NETADMIN_REF=main            ветка или тег
#               NETADMIN_LISTEN=IP:PORT      адрес панели без домена (по умолчанию LAN-адрес узла:8088)
#               NETADMIN_APPLY=1             кнопка «Применить дома» сразу применяет конфиг (по умолчанию 1)
#               NETADMIN_SKIP_DEPS=1         не ставить пакеты
#               NETADMIN_GITHUB_TOKEN=...    токен для приватного репозитория
# Удаление:  curl -fsSL .../install.sh | sudo bash -s -- --uninstall
set -euo pipefail

REPO="${NETADMIN_REPO:-obotkov/home-net}"
REF="${NETADMIN_REF:-main}"
PREFIX=/opt/netadmin
STATE_DIR=/var/lib/netadmin
ENV_FILE=/etc/netadmin.env
UNIT=/etc/systemd/system/netadmin.service
CADDY_SITE=/etc/caddy/netadmin.caddy
CADDY_ENV=/etc/caddy/netadmin.env
CADDY_DROPIN=/etc/systemd/system/caddy.service.d/netadmin.conf
INTERNAL=127.0.0.1:8088
PRIVATE_NETS="127.0.0.1/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 fd00::/8 ::1/128"

say()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mОшибка:\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- аргументы
DOMAIN="${NETADMIN_DOMAIN:-}"; EMAIL="${NETADMIN_EMAIL:-}"; ACME="${NETADMIN_ACME:-}"
CF_TOKEN="${NETADMIN_CF_TOKEN:-}"; ALLOW="${NETADMIN_ALLOW:-}"; NO_DOMAIN=0; UNINSTALL=0
while [ $# -gt 0 ]; do
  case "$1" in
    --domain) DOMAIN="${2:?}"; shift 2 ;;
    --email) EMAIL="${2:?}"; shift 2 ;;
    --acme) ACME="${2:?}"; shift 2 ;;
    --cf-token) CF_TOKEN="${2:?}"; shift 2 ;;
    --allow) ALLOW="${2:?}"; shift 2 ;;
    --no-domain) NO_DOMAIN=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) sed -n '2,24p' "$0" 2>/dev/null || echo "см. README"; exit 0 ;;
    *) die "неизвестный параметр: $1" ;;
  esac
done

[ "$(id -u)" = 0 ] || die "запустите от root: curl ... | sudo bash"
command -v systemctl >/dev/null || die "нужен systemd"

# KEY=VALUE в env-файле: заменить или дописать
set_env() {
  local file=$1 key=$2 val=$3
  touch "$file"; chmod 600 "$file"
  if grep -q "^$key=" "$file"; then
    python3 - "$file" "$key" "$val" <<'PY'
import sys
f, k, v = sys.argv[1:]
lines = open(f).read().splitlines()
open(f, "w").write("\n".join(f"{k}={v}" if l.startswith(k + "=") else l for l in lines) + "\n")
PY
  else
    echo "$key=$val" >> "$file"
  fi
}
get_env() { [ -f "$1" ] && sed -n "s/^$2=//p" "$1" | tail -n1 || true; }

if [ "$UNINSTALL" = 1 ]; then
  say "удаляю netadmin (состояние в $STATE_DIR оставляю)"
  systemctl disable --now netadmin 2>/dev/null || true
  rm -rf "$PREFIX" "$UNIT"
  if [ -f "$CADDY_SITE" ]; then
    rm -f "$CADDY_SITE" "$CADDY_ENV" "$CADDY_DROPIN"
    sed -i '/import netadmin.caddy/d' /etc/caddy/Caddyfile 2>/dev/null || true
    systemctl daemon-reload; systemctl reload-or-restart caddy 2>/dev/null || true
  fi
  systemctl daemon-reload
  say "готово. Ключи и VPS остались в $STATE_DIR, пароль в $ENV_FILE"
  exit 0
fi

# Домен из прошлой установки, если не передан сейчас
if [ "$NO_DOMAIN" = 0 ] && [ -z "$DOMAIN" ]; then
  DOMAIN=$(get_env "$ENV_FILE" NETADMIN_DOMAIN)
  if [ -z "$DOMAIN" ] && [ ! -f "$ENV_FILE" ] && [ -r /dev/tty ] && [ -w /dev/tty ]; then
    printf 'Домен для панели (Enter — без домена, по IP): ' > /dev/tty
    read -r DOMAIN < /dev/tty || DOMAIN=""
    if [ -n "$DOMAIN" ] && [ -z "$EMAIL" ]; then
      printf 'Email для Let'"'"'s Encrypt: ' > /dev/tty; read -r EMAIL < /dev/tty || EMAIL=""
    fi
    if [ -n "$DOMAIN" ] && [ -z "$ACME" ]; then
      printf 'Проверка домена: 1) http — порты 80/443 открыты из интернета  2) cloudflare — через DNS [1]: ' > /dev/tty
      read -r a < /dev/tty || a=1; [ "$a" = 2 ] && ACME=cloudflare
    fi
    if [ "$ACME" = cloudflare ] && [ -z "$CF_TOKEN" ]; then
      printf 'API-токен Cloudflare (Zone:DNS:Edit): ' > /dev/tty; read -rs CF_TOKEN < /dev/tty || true; echo > /dev/tty
    fi
  fi
fi
[ -n "$DOMAIN" ] && [ -z "$EMAIL" ] && EMAIL=$(get_env "$ENV_FILE" NETADMIN_EMAIL)
[ -n "$DOMAIN" ] && [ -z "$ACME" ] && ACME=$(get_env "$ENV_FILE" NETADMIN_ACME)
[ -n "$DOMAIN" ] && [ -z "$ALLOW" ] && ALLOW=$(get_env "$ENV_FILE" NETADMIN_ALLOW)
ACME="${ACME:-http}"; ALLOW="${ALLOW:-private}"
if [ -n "$DOMAIN" ]; then
  [[ "$DOMAIN" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]] || die "некорректный домен: $DOMAIN"
  case "$ACME" in http|cloudflare) ;; *) die "--acme: http или cloudflare" ;; esac
  if [ "$ACME" = cloudflare ] && [ -z "$CF_TOKEN" ] && ! grep -q '^CF_API_TOKEN=' "$CADDY_ENV" 2>/dev/null; then
    die "для --acme cloudflare нужен --cf-token"
  fi
  [ -z "$EMAIL" ] && warn "email не указан: Let's Encrypt не сможет предупредить об истечении сертификата"
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
LAN_IF=$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); exit}}')
LAN_IP=$(ip -4 -o addr show dev "${LAN_IF:-lo}" 2>/dev/null | awk '{print $4; exit}')
if [ ! -f "$ENV_FILE" ]; then
  FIRST=1
  LAN_CIDR=$(python3 -c "import ipaddress,sys; print(ipaddress.ip_interface(sys.argv[1]).network)" "${LAN_IP:-192.168.1.1/24}")
  PASS=$(python3 -c 'import secrets; print(secrets.token_urlsafe(12))')
  umask 077
  cat > "$ENV_FILE" <<EOF
# netadmin — меняйте и делайте: systemctl restart netadmin
NETADMIN_PASSWORD=$PASS
NETADMIN_LISTEN=${NETADMIN_LISTEN:-${LAN_IP%/*}:8088}
NETADMIN_APPLY=${NETADMIN_APPLY:-1}
NETADMIN_STATE=$STATE_DIR/state.json
NETADMIN_OUT=$STATE_DIR/out
# значения по умолчанию для первого запуска (потом правятся в «Настройках»)
NETADMIN_LAN_IF=${LAN_IF:-br-lan}
NETADMIN_LAN_CIDR=$LAN_CIDR
NETADMIN_NAME=$(hostname -s 2>/dev/null | tr 'A-Z' 'a-z' | cut -c1-12 || echo home)
EOF
  umask 022
fi

# SSH-ключ для кнопки «Развернуть по SSH»
[ -f /root/.ssh/id_ed25519 ] || { install -d -m 700 /root/.ssh; ssh-keygen -q -t ed25519 -N '' -f /root/.ssh/id_ed25519 -C netadmin; }

# ---------------------------------------------------------------- домен + Let's Encrypt (Caddy)
install_caddy() {
  if ! command -v caddy >/dev/null; then
    say "ставлю Caddy"
    if command -v apt-get >/dev/null; then
      apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https gnupg >/dev/null
      curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
      curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt > /etc/apt/sources.list.d/caddy-stable.list
      apt-get update -qq && apt-get install -y -qq caddy >/dev/null
    elif command -v dnf >/dev/null; then
      dnf install -y -q 'dnf-command(copr)' && dnf copr enable -y @caddy/caddy && dnf install -y -q caddy
    elif command -v pacman >/dev/null; then
      pacman -S --noconfirm --needed caddy
    else
      die "поставьте Caddy вручную: https://caddyserver.com/docs/install"
    fi
  fi
  if [ "$ACME" = cloudflare ] && ! caddy list-modules 2>/dev/null | grep -q '^dns.providers.cloudflare'; then
    # Сборка Caddy с модулем Cloudflare; системный бинарник не трогаем, подменяем только ExecStart
    say "скачиваю Caddy с модулем DNS Cloudflare"
    case "$(uname -m)" in x86_64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; armv7l) ARCH=armv7 ;; *) die "архитектура $(uname -m)";; esac
    curl -fsSL -o /usr/local/bin/caddy-netadmin.new \
      "https://caddyserver.com/api/download?os=linux&arch=$ARCH&p=github.com%2Fcaddy-dns%2Fcloudflare"
    chmod 755 /usr/local/bin/caddy-netadmin.new
    /usr/local/bin/caddy-netadmin.new list-modules | grep -q '^dns.providers.cloudflare' || die "скачанный Caddy без модуля cloudflare"
    mv /usr/local/bin/caddy-netadmin.new /usr/local/bin/caddy-netadmin
  fi
}

setup_domain() {
  install_caddy
  local caddy_bin; caddy_bin=$(command -v caddy)
  [ "$ACME" = cloudflare ] && caddy_bin=/usr/local/bin/caddy-netadmin

  # порты 80/443 не должны быть заняты кем-то кроме Caddy
  local busy
  busy=$(ss -Hltnp 2>/dev/null | awk '$4 ~ /:(80|443)$/' | grep -v '"caddy' || true)
  [ -n "$busy" ] && warn "порты 80/443 заняты другим процессом, Caddy может не запуститься:"$'\n'"$busy"

  local allow_nets="$ALLOW"
  [ "$ALLOW" = private ] && allow_nets="$PRIVATE_NETS"
  local guard=""
  if [ "$ALLOW" != any ]; then
    guard="	@outside not remote_ip $allow_nets
	respond @outside \"Доступ к панели только из домашней сети или VPN\" 403"
  fi
  local tls=""
  [ "$ACME" = cloudflare ] && tls="	tls {
		dns cloudflare {env.CF_API_TOKEN}
		resolvers 1.1.1.1
	}"
  install -d /etc/caddy
  cat > "$CADDY_SITE" <<EOF
# managed-by netadmin — перезаписывается install.sh
$DOMAIN {
$tls
$guard
	encode gzip
	header {
		Strict-Transport-Security "max-age=31536000"
		X-Content-Type-Options nosniff
		Referrer-Policy no-referrer
		-Server
	}
	reverse_proxy $INTERNAL
}
EOF
  # Caddyfile: глобальный email + import нашего сайта. Стандартный файл из пакета (заглушка на :80) заменяем.
  local cf=/etc/caddy/Caddyfile
  if [ ! -s "$cf" ] || grep -q '/usr/share/caddy' "$cf"; then
    printf '# Caddyfile (создан netadmin)\n{\n}\n\nimport netadmin.caddy\n' > "$cf"
  elif ! grep -q 'import netadmin.caddy' "$cf"; then
    printf '\nimport netadmin.caddy\n' >> "$cf"
  fi
  if [ -n "$EMAIL" ]; then
    python3 - "$cf" "$EMAIL" <<'PY'
import re, sys
f, email = sys.argv[1:]
s = open(f).read()
if re.match(r"\s*(#[^\n]*\n\s*)*\{", s):          # уже есть глобальный блок
    s = re.sub(r"^(\s*email\s+\S+\s*\n)", "", s, flags=re.M)
    s = re.sub(r"\{", "{\n\temail " + email, s, count=1)
else:
    s = "{\n\temail " + email + "\n}\n\n" + s
open(f, "w").write(s)
PY
  fi

  install -d /etc/systemd/system/caddy.service.d
  if [ "$ACME" = cloudflare ]; then
    [ -n "$CF_TOKEN" ] && { umask 077; echo "CF_API_TOKEN=$CF_TOKEN" > "$CADDY_ENV"; umask 022; }
    chown root:caddy "$CADDY_ENV" 2>/dev/null || true; chmod 640 "$CADDY_ENV"
    cat > "$CADDY_DROPIN" <<EOF
[Service]
EnvironmentFile=$CADDY_ENV
ExecStart=
ExecStart=$caddy_bin run --environ --config /etc/caddy/Caddyfile
ExecReload=
ExecReload=$caddy_bin reload --config /etc/caddy/Caddyfile --force
EOF
  else
    rm -f "$CADDY_DROPIN" "$CADDY_ENV"
  fi
  "$caddy_bin" fmt --overwrite "$CADDY_SITE" >/dev/null 2>&1 || true
  CF_API_TOKEN=x "$caddy_bin" validate --config /etc/caddy/Caddyfile >/dev/null 2>"$TMP/caddy.err" \
    || { cat "$TMP/caddy.err" >&2; die "Caddyfile не прошёл проверку"; }

  # DNS: для http-проверки домен должен смотреть на публичный IP
  local dns_ip; dns_ip=$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk '{print $1; exit}')
  if [ -z "$dns_ip" ]; then
    warn "домен $DOMAIN пока не резолвится. Создайте A-запись, Caddy получит сертификат, как только она появится"
  elif [ "$ACME" = http ] && python3 -c "import ipaddress,sys; a=ipaddress.ip_address(sys.argv[1]); sys.exit(not (a.is_private or a in ipaddress.ip_network('100.64.0.0/10')))" "$dns_ip"; then
    warn "$DOMAIN указывает на частный адрес $dns_ip: Let's Encrypt не достучится. Используйте --acme cloudflare"
  fi

  systemctl daemon-reload
  systemctl enable -q caddy
  systemctl restart caddy
  set_env "$ENV_FILE" NETADMIN_DOMAIN "$DOMAIN"
  set_env "$ENV_FILE" NETADMIN_EMAIL "$EMAIL"
  set_env "$ENV_FILE" NETADMIN_ACME "$ACME"
  set_env "$ENV_FILE" NETADMIN_ALLOW "$ALLOW"
  set_env "$ENV_FILE" NETADMIN_LISTEN "$INTERNAL"   # наружу панель отдаёт только Caddy
}

remove_domain() {
  if [ -f "$CADDY_SITE" ]; then
    say "убираю домен из Caddy"
    rm -f "$CADDY_SITE" "$CADDY_ENV" "$CADDY_DROPIN"
    sed -i '/import netadmin.caddy/d' /etc/caddy/Caddyfile 2>/dev/null || true
    systemctl daemon-reload; systemctl reload-or-restart caddy 2>/dev/null || true
  fi
  set_env "$ENV_FILE" NETADMIN_DOMAIN ""
  if [ "$(get_env "$ENV_FILE" NETADMIN_LISTEN)" = "$INTERNAL" ]; then
    set_env "$ENV_FILE" NETADMIN_LISTEN "${NETADMIN_LISTEN:-${LAN_IP%/*}:8088}"
  fi
}

if [ -n "$DOMAIN" ]; then
  setup_domain
elif [ "$NO_DOMAIN" = 1 ]; then
  remove_domain
fi

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
# shellcheck disable=SC1090
. "$ENV_FILE"
echo
if [ -n "${NETADMIN_DOMAIN:-}" ]; then
  say "жду сертификат для $NETADMIN_DOMAIN (до 90 с)…"
  CERT_OK=0
  for _ in $(seq 1 30); do
    if curl -fsS -o /dev/null --max-time 3 --resolve "$NETADMIN_DOMAIN:443:127.0.0.1" "https://$NETADMIN_DOMAIN/" 2>/dev/null \
       || curl -sS -o /dev/null -w '%{http_code}' --max-time 3 --resolve "$NETADMIN_DOMAIN:443:127.0.0.1" "https://$NETADMIN_DOMAIN/" 2>/dev/null | grep -qE '^(401|403)$'; then
      CERT_OK=1; break
    fi
    sleep 3
  done
  if [ "$CERT_OK" = 1 ]; then
    say "netadmin работает: https://$NETADMIN_DOMAIN   логин: admin"
    say "сертификат Let's Encrypt получен, Caddy продлевает его сам (примерно за 30 дней до истечения)"
  else
    warn "сертификат пока не получен. Смотрите: journalctl -u caddy -n 50"
    warn "частые причины: нет A-записи, порты 80/443 не проброшены на этот узел (для --acme http), неверный токен Cloudflare"
    say "панель доступна локально: http://$NETADMIN_LISTEN"
  fi
  [ "${NETADMIN_ALLOW:-private}" = private ] && say "по домену панель открыта только из LAN/VPN (--allow any, чтобы открыть всем)"
else
  say "netadmin работает: http://$NETADMIN_LISTEN   логин: admin"
fi
if [ "$FIRST" = 1 ]; then
  say "пароль: $NETADMIN_PASSWORD   (хранится в $ENV_FILE)"
  say "LAN: $NETADMIN_LAN_IF $NETADMIN_LAN_CIDR — проверьте во вкладке «Настройки»"
else
  say "код обновлён, состояние и пароль не тронуты"
fi
say "ключ для VPS (добавьте в ~/.ssh/authorized_keys на каждом VPS или: ssh-copy-id -i /root/.ssh/id_ed25519 root@VPS):"
cat /root/.ssh/id_ed25519.pub
