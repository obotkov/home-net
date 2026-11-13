"""netadmin: веб-админка домашней сети Xray -> WireGuard -> BIRD/OSPF.

Только стандартная библиотека Python 3.9+. Запуск:  python3 -m netadmin
Переменные окружения:
  NETADMIN_LISTEN    адрес:порт (по умолчанию 127.0.0.1:8088)
  NETADMIN_PASSWORD  пароль для входа (логин admin); если не задан, генерируется и печатается
  NETADMIN_STATE     файл состояния (по умолчанию ./netadmin-state.json)
  NETADMIN_APPLY     1 = кнопка «Применить» реально выполняет apply.sh на этом узле (нужен root)
  NETADMIN_OUT       куда складывать сгенерированные файлы (по умолчанию ./out)
  NETADMIN_DEMO      1 = демо-данные вместо wg/birdc
"""
import base64
import hmac
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import urllib.request
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import collectors, generator, updater, webauthn
from .store import Store

STATIC = Path(__file__).parent / "static"
SECRET_FIELDS = ("wg", "xray")


def public_vps(store, v):
    out = {k: val for k, val in v.items() if k not in SECRET_FIELDS}
    out["client_link"] = generator.client_link(store.home, v)
    out["iface"] = generator.home_iface(v)
    out["wg_pub"] = {"home": v["wg"]["home_pub"], "vps": v["wg"]["vps_pub"]}
    if store.home.get("mode") == "keenetic":
        out["keenetic_cli"] = generator.keenetic_cli(store.home, v)
    return out


class App:
    def __init__(self):
        self.store = Store(os.environ.get("NETADMIN_STATE", "netadmin-state.json"))
        self.password = os.environ.get("NETADMIN_PASSWORD") or secrets.token_urlsafe(12)
        self.generated_password = "NETADMIN_PASSWORD" not in os.environ
        self.apply_enabled = os.environ.get("NETADMIN_APPLY") == "1"
        self.out_dir = Path(os.environ.get("NETADMIN_OUT", "out"))
        self.home_apply = {"status": "never", "log": "", "at": None}
        self.sessions = {}     # token -> срок действия
        self.challenges = {}   # challenge -> (вид, срок действия)
        self.fails = {}        # ip -> [время неудачных попыток]
        self.lock = threading.Lock()

    SESSION_TTL = 7 * 24 * 3600

    def new_session(self):
        tok = secrets.token_urlsafe(32)
        with self.lock:
            now = time.time()
            self.sessions = {k: v for k, v in self.sessions.items() if v > now}
            self.sessions[tok] = now + self.SESSION_TTL
        return tok

    def session_ok(self, tok):
        exp = self.sessions.get(tok or "")
        return bool(exp and exp > time.time())

    def new_challenge(self, kind):
        ch = webauthn.challenge()
        with self.lock:
            now = time.time()
            self.challenges = {k: v for k, v in self.challenges.items() if v[1] > now}
            self.challenges[ch] = (kind, now + 300)
        return ch

    def take_challenge(self, ch, kind):
        with self.lock:
            v = self.challenges.pop(ch or "", None)
        if not v or v[0] != kind or v[1] < time.time():
            raise webauthn.WebAuthnError("challenge устарел, попробуйте ещё раз")

    def blocked(self, ip):
        now = time.time()
        f = [t for t in self.fails.get(ip, []) if now - t < 600]
        self.fails[ip] = f
        return len(f) >= 5

    @property
    def passkeys(self):
        return self.store.data.setdefault("passkeys", [])

    # ------------------------------------------------ actions
    def write_out(self, files):
        for name, content in files.items():
            p = self.out_dir / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
            os.chmod(p, 0o700 if name.endswith(".sh") else 0o600)
        return str(self.out_dir.resolve())

    def _run_bg(self, target, steps, demo_lines, secrets_=()):
        """steps: [(cmd, stdin_text, extra_env)] — выполняются по очереди, до первой ошибки."""
        target.update(status="running", log="", at=int(time.time()))

        def scrub(text):
            for sec in secrets_:
                if sec:
                    text = text.replace(sec, "***")
            return text

        def work():
            if collectors.demo_mode():
                for line in demo_lines:
                    time.sleep(0.6)
                    target["log"] += line + "\n"
                target["status"] = "ok"
            else:
                ok = True
                for cmd, stdin_text, extra_env in steps:
                    try:
                        env = {**os.environ, **(extra_env or {})}
                        p = subprocess.run(cmd, input=stdin_text, capture_output=True, text=True, timeout=900, env=env)
                        target["log"] = (target["log"] + scrub(p.stdout + p.stderr))[-20000:]
                        if p.returncode != 0:
                            ok = False
                            break
                    except Exception as e:  # noqa: BLE001
                        target["log"] += f"\n{scrub(str(e))}"
                        ok = False
                        break
                target["status"] = "ok" if ok else "error"
            self.store.save()

        threading.Thread(target=work, daemon=True).start()

    SSH_KEY = "/root/.ssh/id_ed25519"

    @staticmethod
    def detect_public_ip():
        for url in ("https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"):
            try:
                with urllib.request.urlopen(url, timeout=5) as r:
                    ip = r.read().decode().strip()
                socket.inet_aton(ip)
                return ip
            except (OSError, ValueError):
                continue
        try:  # без интернета: адрес исходящего интерфейса
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sk:
                sk.connect(("1.1.1.1", 53))
                return sk.getsockname()[0]
        except OSError:
            raise ValueError("Не удалось определить публичный IP этого сервера: добавьте его через форму")

    @staticmethod
    def free_tcp_port(candidates=(443, 8443, 9443, 10443)):
        """Первый свободный порт для Xray (443 обычно занят Caddy, если панель открыта по домену)."""
        for port in candidates:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sk:
                sk.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    sk.bind(("0.0.0.0", port))
                    return port
                except OSError:
                    continue
        return 8443

    def add_self(self):
        """Добавить сервер, на котором работает панель, и сразу поставить на него AmneziaWG и Xray."""
        if any(v.get("local") for v in self.store.vps):
            raise ValueError("Этот сервер уже добавлен")
        if collectors.demo_mode():
            ip, port = "198.51.100.10", 8443
        else:
            ip, port = self.detect_public_ip(), self.free_tcp_port()
        base = re.sub(r"[^a-z0-9-]", "", socket.gethostname().split(".")[0].lower()).lstrip("0123456789-")[:12] or "main"
        name, n = base, 2
        while any(v["name"] == name for v in self.store.vps):
            name = f"{base[:10]}{n}"
            n += 1
        v = self.store.add_vps({"name": name, "label": "Этот сервер (панель)", "public_ip": ip,
                                "xray_port": port, "local": True})
        self.deploy_vps(v)
        return v

    def deploy_vps(self, v, password=None):
        """Разворачивание VPS по SSH. Пароль (если дан) используется один раз: ставим на VPS ключ узла
        через sshpass + ssh-copy-id, дальше всё идёт по ключу. Пароль нигде не сохраняется."""
        script = generator.bootstrap_for(self.store.home, v)
        self.write_out(generator.all_files(self.store.home, self.store.vps, v))
        if v.get("local"):  # сервер с панелью: запускаем локально, SSH не нужен
            v.setdefault("deploy", {})
            if os.geteuid() != 0 and not collectors.demo_mode():
                raise ValueError("Панель запущена не от root: установка на этот сервер невозможна")
            self._run_bg(v["deploy"], [(["bash", "-s"], script, None)],
                         ["[демо] локальная установка", "== пакеты", "== AmneziaWG", "== конфиги", "== сервисы",
                          "interface: awg-home", f"  listening port: {v['awg']['port']}", "== готово"])
            return
        target = f"{v['ssh_user']}@{v['public_ip']}"
        common = ["-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=15", "-p", str(v["ssh_port"])]
        steps = []
        demo = ["[демо] ssh %s" % target]
        if password:
            if not shutil.which("sshpass"):
                raise ValueError("Для входа по паролю нужен sshpass: sudo apt install sshpass (или обновите установку)")
            if not os.path.exists(self.SSH_KEY + ".pub"):
                subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", self.SSH_KEY, "-C", "netadmin"],
                               check=True)
            steps.append((["sshpass", "-e", "ssh-copy-id", "-i", self.SSH_KEY + ".pub",
                           "-o", "PreferredAuthentications=password,keyboard-interactive",
                           "-o", "PubkeyAuthentication=no", *common, target], None, {"SSHPASS": password}))
            demo.append("[демо] вход по паролю, ключ узла добавлен на VPS")
        remote = "bash -s"
        stdin = script
        if v["ssh_user"] != "root":
            if password:  # sudo читает пароль первой строкой stdin, остальное получает bash
                remote, stdin = "sudo -S -p '' bash -s", password + "\n" + script
            else:
                remote = ("sudo -n true 2>/dev/null || { echo 'sudo просит пароль: нажмите «Развернуть» и укажите пароль SSH' >&2; exit 1; }; "
                          "sudo -n bash -s")
        steps.append((["ssh", "-o", "BatchMode=yes", "-i", self.SSH_KEY, *common, target, remote], stdin, None))
        v.setdefault("deploy", {})
        if self.store.home.get("mode") == "keenetic":
            demo += ["== пакеты", "== AmneziaWG", "== конфиги", "== сервисы", "interface: awg-home",
                     f"  listening port: {v['awg']['port']}", "== готово. Теперь импортируйте конфиг в Keenetic"]
        else:
            demo += ["== пакеты", "== конфиги", "== фаервол: WireGuard доступен только через локальный Xray",
                     "== сервисы", "interface: wg-home", "ospf1      OSPF       ---        up     Running", "== готово"]
        self._run_bg(v["deploy"], steps, demo, secrets_=(password,))

    def apply_home(self):
        if self.store.home.get("mode") == "keenetic":
            raise ValueError("В режиме Keenetic домашнего Linux-узла нет: импортируйте конфиг в роутер (карточка VPS → «Keenetic»)")
        files = generator.all_files(self.store.home, self.store.vps)
        path = self.write_out(files)
        if not self.apply_enabled:
            self.home_apply.update(status="written", at=int(time.time()),
                                   log=f"Файлы записаны в {path}/home.\nЗапустите на домашнем узле: sudo bash {path}/home/apply.sh\n"
                                       "(или запустите админку с NETADMIN_APPLY=1 от root, чтобы применять кнопкой)")
            return
        self._run_bg(self.home_apply, [(["bash", "-s"], files["home/apply.sh"], None)], ["[демо] применено"])


APP = None


class Handler(BaseHTTPRequestHandler):
    server_version = "netadmin"

    def log_message(self, fmt, *args):
        pass

    # ------------------------------------------------ helpers
    def _cookie(self, name):
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v
        return None

    def _client_ip(self):
        ip = self.client_address[0]
        if ip in ("127.0.0.1", "::1") and self.headers.get("X-Forwarded-For"):
            ip = self.headers["X-Forwarded-For"].split(",")[0].strip()
        return ip

    def _origin(self):
        host = self.headers.get("Host") or "localhost"
        proto = self.headers.get("X-Forwarded-Proto") or "http"
        rp_id = host.rsplit(":", 1)[0] if not host.endswith("]") else host
        return f"{proto}://{host}", rp_id.strip("[]"), proto == "https"

    def _authed(self):
        if APP.session_ok(self._cookie("na_session")):
            return True
        h = self.headers.get("Authorization", "")  # для скриптов: curl -u admin:пароль
        if h.startswith("Basic "):
            try:
                user, _, pw = base64.b64decode(h[6:]).decode().partition(":")
                return user == "admin" and hmac.compare_digest(pw, APP.password)
            except Exception:  # noqa: BLE001
                return False
        return False

    def _auth(self):
        if self._authed():
            return True
        self._send(401, {"error": "нужен вход", "login": True})
        return False

    def _set_session(self, body):
        _, _, secure = self._origin()
        tok = APP.new_session()
        cookie = f"na_session={tok}; Path=/; HttpOnly; SameSite=Strict; Max-Age={APP.SESSION_TTL}"
        if secure:
            cookie += "; Secure"
        self._send(200, body, extra={"Set-Cookie": cookie})

    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        if not isinstance(body, (bytes, str)):
            body = json.dumps(body, ensure_ascii=False)
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        for k, val in (extra or {}).items():
            self.send_header(k, val)
        self.end_headers()
        self.wfile.write(body)

    def _json_body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 100_000:
            raise ValueError("слишком большой запрос")
        return json.loads(self.rfile.read(n) or b"{}")

    def _same_origin(self):
        # защита от CSRF: изменяющие запросы только с нашей страницы
        return self.headers.get("X-Requested-With") == "netadmin"

    # ------------------------------------------------ routing
    def do_GET(self):
        s, path = APP.store, self.path.split("?")[0]
        if path in ("/", "/login"):
            page = "index.html" if self._authed() and path == "/" else "login.html"
            return self._send(200, (STATIC / page).read_bytes(), "text/html; charset=utf-8")
        if not self._auth():
            return
        if path == "/api/passkeys":
            return self._send(200, [{k: c[k] for k in ("id", "name", "created", "last_used")} for c in APP.passkeys])
        if path == "/api/state":
            st = collectors.collect(s)
            st["home_apply"] = APP.home_apply
            st["apply_enabled"] = APP.apply_enabled
            return self._send(200, st)
        if path == "/api/vps":
            return self._send(200, [public_vps(s, v) for v in s.vps])
        if path == "/api/update/check":
            try:
                return self._send(200, updater.check())
            except RuntimeError as e:
                return self._send(502, {"error": str(e)})
        if path == "/api/update/status":
            return self._send(200, updater.status())
        if path == "/api/home/files":
            return self._send(200, generator.all_files(s.home, s.vps))
        m = re.match(r"^/api/vps/(\w+)(/files|/bootstrap\.sh|/deploy|/keenetic\.conf)?$", path)
        if m:
            v = s.get_vps(m[1])
            if not v:
                return self._send(404, {"error": "нет такого VPS"})
            if m[2] == "/files":
                return self._send(200, generator.all_files(s.home, s.vps, v))
            if m[2] == "/bootstrap.sh":
                return self._send(200, generator.bootstrap_for(s.home, v), "text/x-shellscript; charset=utf-8",
                                  {"Content-Disposition": f'attachment; filename="bootstrap-{v["name"]}.sh"'})
            if m[2] == "/deploy":
                return self._send(200, v.get("deploy", {}))
            if m[2] == "/keenetic.conf":
                return self._send(200, generator.keenetic_conf(s.home, v), "text/plain; charset=utf-8",
                                  {"Content-Disposition": f'attachment; filename="keenetic-{v["name"]}.conf"'})
            return self._send(200, public_vps(s, v))
        self._send(404, {"error": "not found"})

    def _auth_routes(self, path, body):
        """Вход: пароль и passkey. Возвращает True, если запрос обработан."""
        origin, rp_id, _ = self._origin()
        ip = self._client_ip()
        if path == "/auth/login":
            if APP.blocked(ip):
                self._send(429, {"error": "слишком много попыток, подождите 10 минут"})
            elif hmac.compare_digest(str(body.get("password", "")), APP.password):
                APP.fails.pop(ip, None)
                self._set_session({"ok": True})
            else:
                APP.fails.setdefault(ip, []).append(time.time())
                time.sleep(1)
                self._send(401, {"error": "неверный пароль"})
            return True
        if path == "/auth/passkey/options":
            self._send(200, {"challenge": APP.new_challenge("get"), "rpId": rp_id, "timeout": 60000,
                             "userVerification": "preferred",
                             "allowCredentials": [{"type": "public-key", "id": c["id"]} for c in APP.passkeys]})
            return True
        if path == "/auth/passkey/login":
            try:
                if APP.blocked(ip):
                    raise webauthn.WebAuthnError("слишком много попыток, подождите 10 минут")
                cred = next((c for c in APP.passkeys if c["id"] == body.get("id")), None)
                if not cred:
                    raise webauthn.WebAuthnError("этот passkey не зарегистрирован в панели")
                resp = body.get("response") or {}
                ch = webauthn.unb64u(resp.get("clientDataJSON", ""))
                APP.take_challenge(json.loads(ch).get("challenge") if ch else None, "get")
                cred["sign_count"] = webauthn.verify_assertion(resp, cred, json.loads(ch)["challenge"], origin, rp_id)
                cred["last_used"] = int(time.time())
                APP.store.save()
                APP.fails.pop(ip, None)
                self._set_session({"ok": True})
            except (webauthn.WebAuthnError, KeyError, ValueError, TypeError) as e:
                APP.fails.setdefault(ip, []).append(time.time())
                self._send(401, {"error": f"passkey: {e}"})
            return True
        return False

    def _mutate(self, method):
        if not self._same_origin():
            return self._send(403, {"error": "csrf"})
        s, path = APP.store, self.path.split("?")[0]
        try:
            body = self._json_body() if method in ("POST", "PATCH") else {}
        except ValueError as e:
            return self._send(400, {"error": str(e)})
        if method == "POST" and self._auth_routes(path, body):
            return
        if not self._auth():
            return
        try:
            if method == "POST" and path == "/auth/logout":
                APP.sessions.pop(self._cookie("na_session") or "", None)
                return self._send(200, {"ok": True}, extra={"Set-Cookie": "na_session=; Path=/; Max-Age=0"})
            if method == "POST" and path == "/api/passkeys/options":
                origin, rp_id, _ = self._origin()
                return self._send(200, {
                    "challenge": APP.new_challenge("create"), "rp": {"id": rp_id, "name": "netadmin"},
                    "user": {"id": webauthn.b64u(b"netadmin-admin"), "name": "admin", "displayName": "admin"},
                    "pubKeyCredParams": [{"type": "public-key", "alg": -7}, {"type": "public-key", "alg": -257}],
                    "timeout": 60000, "attestation": "none",
                    "authenticatorSelection": {"residentKey": "preferred", "userVerification": "preferred"},
                    "excludeCredentials": [{"type": "public-key", "id": c["id"]} for c in APP.passkeys]})
            if method == "POST" and path == "/api/passkeys":
                origin, rp_id, _ = self._origin()
                resp = body.get("response") or {}
                try:
                    chal = json.loads(webauthn.unb64u(resp.get("clientDataJSON", "")))["challenge"]
                    APP.take_challenge(chal, "create")
                    cred = webauthn.verify_registration(resp, chal, origin, rp_id)
                except (webauthn.WebAuthnError, KeyError, ValueError) as e:
                    return self._send(400, {"error": f"passkey: {e}"})
                cred.update(name=(str(body.get("name") or "").strip()[:40] or "passkey"),
                            created=int(time.time()), last_used=None, rp_id=rp_id)
                APP.passkeys.append(cred)
                s.save()
                return self._send(201, {"ok": True, "id": cred["id"]})
            m = re.match(r"^/api/passkeys/([\w-]+)$", path)
            if method == "DELETE" and m:
                before = len(APP.passkeys)
                s.data["passkeys"] = [c for c in APP.passkeys if c["id"] != m[1]]
                if len(APP.passkeys) == before:
                    return self._send(404, {"error": "нет такого passkey"})
                s.save()
                return self._send(200, {"ok": True})
            if method == "POST" and path == "/api/vps/self":
                return self._send(201, public_vps(s, APP.add_self()))
            if method == "POST" and path == "/api/vps":
                return self._send(201, public_vps(s, s.add_vps(body)))
            if method == "PATCH" and path == "/api/home":
                return self._send(200, s.update_home(body))
            if method == "POST" and path == "/api/update/apply":
                try:
                    return self._send(202, updater.start(demo=collectors.demo_mode()))
                except RuntimeError as e:
                    return self._send(409, {"error": str(e)})
            if method == "POST" and path == "/api/home/apply":
                APP.apply_home()
                return self._send(202, APP.home_apply)
            m = re.match(r"^/api/vps/(\w+)(/deploy)?$", path)
            if m:
                if method == "DELETE" and not m[2]:
                    s.delete_vps(m[1])
                    return self._send(200, {"ok": True})
                if method == "PATCH" and not m[2]:
                    return self._send(200, public_vps(s, s.update_vps(m[1], body)))
                if method == "POST" and m[2]:
                    v = s.get_vps(m[1])
                    if not v:
                        raise KeyError(m[1])
                    APP.deploy_vps(v, (body.get("password") or None) if isinstance(body, dict) else None)
                    return self._send(202, v["deploy"])
            self._send(404, {"error": "not found"})
        except KeyError:
            self._send(404, {"error": "нет такого VPS"})
        except (ValueError, TypeError) as e:
            self._send(400, {"error": str(e)})

    def do_POST(self):
        self._mutate("POST")

    def do_PATCH(self):
        self._mutate("PATCH")

    def do_DELETE(self):
        self._mutate("DELETE")


def main():
    global APP
    APP = App()
    host, _, port = os.environ.get("NETADMIN_LISTEN", "127.0.0.1:8088").rpartition(":")
    srv = ThreadingHTTPServer((host or "127.0.0.1", int(port)), Handler)
    print(f"netadmin: http://{host}:{port}  логин admin")
    if APP.generated_password:
        print(f"пароль (задайте свой через NETADMIN_PASSWORD): {APP.password}")
    if collectors.demo_mode():
        print("демо-режим: wg не найден или NETADMIN_DEMO=1")
    srv.serve_forever()


if __name__ == "__main__":
    main()
