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
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import collectors, generator, updater
from .store import Store

STATIC = Path(__file__).parent / "static"
SECRET_FIELDS = ("wg", "xray")


def public_vps(store, v):
    out = {k: val for k, val in v.items() if k not in SECRET_FIELDS}
    out["client_link"] = generator.client_link(store.home, v)
    out["iface"] = generator.home_iface(v)
    out["wg_pub"] = {"home": v["wg"]["home_pub"], "vps": v["wg"]["vps_pub"]}
    return out


class App:
    def __init__(self):
        self.store = Store(os.environ.get("NETADMIN_STATE", "netadmin-state.json"))
        self.password = os.environ.get("NETADMIN_PASSWORD") or secrets.token_urlsafe(12)
        self.generated_password = "NETADMIN_PASSWORD" not in os.environ
        self.apply_enabled = os.environ.get("NETADMIN_APPLY") == "1"
        self.out_dir = Path(os.environ.get("NETADMIN_OUT", "out"))
        self.home_apply = {"status": "never", "log": "", "at": None}

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

    def deploy_vps(self, v, password=None):
        """Разворачивание VPS по SSH. Пароль (если дан) используется один раз: ставим на VPS ключ узла
        через sshpass + ssh-copy-id, дальше всё идёт по ключу. Пароль нигде не сохраняется."""
        script = generator.vps_bootstrap(self.store.home, v)
        self.write_out(generator.all_files(self.store.home, self.store.vps, v))
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
        self._run_bg(v["deploy"], steps, demo + [
            "== пакеты", "== конфиги", "== фаервол: WireGuard доступен только через локальный Xray", "== сервисы",
            "interface: wg-home", "ospf1      OSPF       ---        up     Running", "== готово"], secrets_=(password,))

    def apply_home(self):
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
    def _auth(self):
        h = self.headers.get("Authorization", "")
        if h.startswith("Basic "):
            try:
                user, _, pw = base64.b64decode(h[6:]).decode().partition(":")
                if user == "admin" and hmac.compare_digest(pw, APP.password):
                    return True
            except Exception:  # noqa: BLE001
                pass
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="netadmin"')
        self.end_headers()
        return False

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
        if not self._auth():
            return
        s, path = APP.store, self.path.split("?")[0]
        if path == "/":
            return self._send(200, (STATIC / "index.html").read_bytes(), "text/html; charset=utf-8")
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
        m = re.match(r"^/api/vps/(\w+)(/files|/bootstrap\.sh|/deploy)?$", path)
        if m:
            v = s.get_vps(m[1])
            if not v:
                return self._send(404, {"error": "нет такого VPS"})
            if m[2] == "/files":
                return self._send(200, generator.all_files(s.home, s.vps, v))
            if m[2] == "/bootstrap.sh":
                return self._send(200, generator.vps_bootstrap(s.home, v), "text/x-shellscript; charset=utf-8",
                                  {"Content-Disposition": f'attachment; filename="bootstrap-{v["name"]}.sh"'})
            if m[2] == "/deploy":
                return self._send(200, v.get("deploy", {}))
            return self._send(200, public_vps(s, v))
        self._send(404, {"error": "not found"})

    def _mutate(self, method):
        if not self._auth():
            return
        if not self._same_origin():
            return self._send(403, {"error": "csrf"})
        s, path = APP.store, self.path.split("?")[0]
        try:
            body = self._json_body() if method in ("POST", "PATCH") else {}
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
