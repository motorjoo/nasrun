#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nasrun — AI 코딩 에이전트(Claude Code, Codex 등)용 NAS·서버 SSH/sudo 브리지
https://github.com/motorjoo/nasrun  (MIT, HWAYOUNGSYSTEMS / PARA)

Claude Code가 NAS 명령을 직접 실행하고 결과(stdout/stderr/종료코드)를 그대로 받게 해 준다.
 - sudo 비밀번호는 Windows 자격 증명 관리자(keyring)에 저장 → 세션/로그에 절대 노출 안 됨
 - sudo 명령은 실행 전에 PC 화면에 승인 팝업 (기본 120초 무응답 시 거부)
 - 모든 실행은 nasrun.log 에 기록 (비밀번호는 마스킹)

사용 예:
  python nasrun.py setup                      # 최초 1회, 터미널에서 직접
  python nasrun.py test
  python nasrun.py run "df -h"
  python nasrun.py run --sudo "docker ps"
  python nasrun.py run --sudo - < script.sh    # 여러 줄 스크립트는 stdin으로
"""
import argparse
import datetime
import getpass
import json
import os
import re
import shlex
import socket
import sys
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "nasrun.json")
LOG_PATH = os.path.join(BASE_DIR, "nasrun.log")
KNOWN_HOSTS_PATH = os.path.join(BASE_DIR, "nasrun_known_hosts")
KEYRING_SERVICE = "nasrun"

# Synology의 비대화형 SSH 세션은 PATH에 /usr/local/bin(docker 등)이 빠져 있음
REMOTE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

DEFAULT_CONFIG = {
    "default_host": "nas",
    "hosts": {
        "nas": {
            "hostname": "192.168.0.10",
            "port": 22,
            "username": "admin",
            "key_file": "",
            "confirm": "sudo",
            "auto_approve": [
                r"^docker (ps|images|logs|inspect|stats --no-stream)\b",
                r"^(ls|cat|df|du|whoami|id|uptime|free|ps|top -bn1)\b",
            ],
            "confirm_timeout_sec": 120,
        }
    },
}

# 표준출력 인코딩 고정 (Windows cp949 콘솔에서 한글/특수문자 깨짐 방지)
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


# ───────────────────────── 설정 / 비밀번호 ─────────────────────────
def load_config():
    if not os.path.exists(CONFIG_PATH):
        return None
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def save_config(cfg):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


def get_host_cfg(cfg, name):
    name = name or cfg.get("default_host")
    if name not in cfg.get("hosts", {}):
        die(f"[nasrun] 호스트 '{name}' 가 nasrun.json 에 없습니다.", 2)
    h = dict(DEFAULT_CONFIG["hosts"]["nas"])
    h.update(cfg["hosts"][name])
    h["_name"] = name
    return h


def keyring_user(h):
    return f"{h['username']}@{h['hostname']}"


def get_password(h):
    try:
        import keyring
    except ImportError:
        die("[nasrun] keyring 모듈이 없습니다: pip install keyring", 2)
    pw = keyring.get_password(KEYRING_SERVICE, keyring_user(h))
    return pw


def set_password(h):
    import keyring
    pw = getpass.getpass(f"{keyring_user(h)} 비밀번호 (입력 내용은 보이지 않음): ")
    pw2 = getpass.getpass("한 번 더: ")
    if pw != pw2:
        die("[nasrun] 비밀번호가 일치하지 않습니다.", 2)
    keyring.set_password(KEYRING_SERVICE, keyring_user(h), pw)
    print("[nasrun] Windows 자격 증명 관리자에 저장했습니다.")


# ───────────────────────── 로그 ─────────────────────────
def log(h, cmd, sudo, status, secret=None):
    line = cmd.replace("\n", "\\n")
    if secret:
        line = line.replace(secret, "****")
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(f"{ts}\t{h['_name']}\t{'sudo' if sudo else 'user'}\t{status}\t{line}\n")


def die(msg, code=1):
    print(msg, file=sys.stderr)
    sys.exit(code)


# ───────────────────────── 승인 팝업 ─────────────────────────
def need_confirm(h, cmd, sudo):
    mode = h.get("confirm", "sudo")
    if mode == "never":
        return False
    if mode == "sudo" and not sudo:
        return False
    stripped = cmd.strip()
    if "\n" not in stripped and not re.search(r"[;&|`$<>]", stripped):
        for pat in h.get("auto_approve", []):
            if re.search(pat, stripped):
                return False
    return True


def ask_approval(h, cmd, sudo):
    """PC 화면에 승인 창. True=승인, False=거부/시간초과."""
    timeout = int(h.get("confirm_timeout_sec", 120))
    try:
        import tkinter as tk
    except Exception:
        print("[nasrun] tkinter 사용 불가 → 승인 창을 띄울 수 없어 거부합니다.", file=sys.stderr)
        return False

    result = {"ok": False}
    try:
        root = tk.Tk()
    except Exception as e:
        print(f"[nasrun] 승인 창 생성 실패({e}) → 거부합니다.", file=sys.stderr)
        return False

    root.title("nasrun — NAS 명령 승인")
    root.attributes("-topmost", True)
    root.geometry("720x380")
    tag = "sudo (root 권한)" if sudo else "일반 사용자"
    tk.Label(root, text=f"대상: {h['username']}@{h['hostname']}   권한: {tag}",
             font=("Malgun Gothic", 11, "bold"), fg="#b00020" if sudo else "#000").pack(anchor="w", padx=12, pady=(12, 4))
    txt = tk.Text(root, wrap="word", font=("Consolas", 11), height=12)
    txt.insert("1.0", cmd)
    txt.configure(state="disabled")
    txt.pack(fill="both", expand=True, padx=12)
    lbl = tk.Label(root, text="", font=("Malgun Gothic", 9), fg="#666")
    lbl.pack(anchor="w", padx=12)
    bar = tk.Frame(root)
    bar.pack(fill="x", padx=12, pady=10)

    def approve(_=None):
        result["ok"] = True
        root.destroy()

    def deny(_=None):
        result["ok"] = False
        root.destroy()

    tk.Button(bar, text="승인 (Enter)", width=14, command=approve, bg="#1b5e20", fg="white").pack(side="right", padx=4)
    tk.Button(bar, text="거부 (Esc)", width=14, command=deny).pack(side="right", padx=4)
    root.bind("<Return>", approve)
    root.bind("<Escape>", deny)
    root.protocol("WM_DELETE_WINDOW", deny)

    remaining = {"t": timeout}

    def tick():
        if remaining["t"] <= 0:
            deny()
            return
        lbl.configure(text=f"{remaining['t']}초 후 자동 거부")
        remaining["t"] -= 1
        root.after(1000, tick)

    tick()
    root.lift()
    root.focus_force()
    root.mainloop()
    return result["ok"]


# ───────────────────────── SSH ─────────────────────────
def connect(h, password):
    try:
        import paramiko
    except ImportError:
        die("[nasrun] paramiko 모듈이 없습니다: pip install paramiko", 2)
    client = paramiko.SSHClient()
    if os.path.exists(KNOWN_HOSTS_PATH):
        client.load_host_keys(KNOWN_HOSTS_PATH)
    else:
        open(KNOWN_HOSTS_PATH, "a").close()
        client.load_host_keys(KNOWN_HOSTS_PATH)
    # 최초 접속 시 호스트 키를 저장(TOFU), 이후 키가 바뀌면 접속 거부
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kw = dict(hostname=h["hostname"], port=int(h.get("port", 22)), username=h["username"],
              timeout=15, banner_timeout=15, auth_timeout=15,
              allow_agent=False, look_for_keys=False)
    key_file = os.path.expanduser(h.get("key_file") or "")
    if key_file and os.path.exists(key_file):
        kw["key_filename"] = key_file
    elif password:
        kw["password"] = password
    else:
        die("[nasrun] 로그인 수단이 없습니다. 'python nasrun.py set-password' 로 비밀번호를 저장하거나 key_file 을 설정하세요.", 2)
    try:
        client.connect(**kw)
    except paramiko.BadHostKeyException:
        die("[nasrun] NAS 호스트 키가 바뀌었습니다! 의도한 변경이면 nasrun_known_hosts 에서 해당 줄을 지우세요.", 3)
    except paramiko.AuthenticationException:
        die("[nasrun] SSH 인증 실패 (아이디/비밀번호/키 확인).", 3)
    except (socket.error, paramiko.SSHException) as e:
        die(f"[nasrun] SSH 접속 실패: {e}", 3)
    client.save_host_keys(KNOWN_HOSTS_PATH)
    return client


def build_remote(cmd, sudo):
    if sudo:
        # -k: 캐시된 sudo 인증 무시 → 비밀번호를 항상 stdin 첫 줄에서 읽음
        # -S: stdin 으로 비밀번호, -p '': 프롬프트 출력 안 함
        # exec </dev/null: 실행되는 명령이 남은 stdin(비밀번호)을 읽지 못하게 차단
        inner = "exec </dev/null; " + cmd
        return f"sudo -k -S -p '' env PATH={REMOTE_PATH} sh -c {shlex.quote(inner)}"
    return f"PATH={REMOTE_PATH}; export PATH; exec </dev/null; sh -c {shlex.quote(cmd)}"


def run_remote(client, remote, stdin_data, timeout, secret):
    chan = client.get_transport().open_session()
    chan.settimeout(1.0)
    chan.exec_command(remote)
    if stdin_data is not None:
        chan.sendall(stdin_data.encode("utf-8"))
    chan.shutdown_write()

    out_dec = _Dec()
    err_dec = _Dec()
    start = time.time()

    def emit(stream, text):
        if not text:
            return
        if secret:
            text = text.replace(secret, "****")
        stream.write(text)
        stream.flush()

    while True:
        got = False
        if chan.recv_ready():
            emit(sys.stdout, out_dec.feed(chan.recv(65536)))
            got = True
        if chan.recv_stderr_ready():
            emit(sys.stderr, err_dec.feed(chan.recv_stderr(65536)))
            got = True
        if chan.exit_status_ready() and not chan.recv_ready() and not chan.recv_stderr_ready():
            break
        if timeout and time.time() - start > timeout:
            chan.close()
            emit(sys.stderr, f"\n[nasrun] 시간 초과({timeout}s) — 원격 명령을 끊었습니다.\n")
            return 124
        if not got:
            time.sleep(0.05)
    emit(sys.stdout, out_dec.flush())
    emit(sys.stderr, err_dec.flush())
    return chan.recv_exit_status()


class _Dec:
    """UTF-8 멀티바이트가 청크 경계에서 잘려도 깨지지 않게."""
    def __init__(self):
        import codecs
        self.d = codecs.getincrementaldecoder("utf-8")(errors="replace")

    def feed(self, b):
        return self.d.decode(b)

    def flush(self):
        return self.d.decode(b"", final=True)


# ───────────────────────── 명령 ─────────────────────────
def cmd_setup(args):
    cfg = load_config() or json.loads(json.dumps(DEFAULT_CONFIG))
    name = args.host or cfg.get("default_host", "nas")
    h = cfg["hosts"].setdefault(name, dict(DEFAULT_CONFIG["hosts"]["nas"]))
    print(f"[nasrun] '{name}' 설정 (Enter = 현재값 유지)")
    for key, label in (("hostname", "NAS 주소(IP/도메인)"), ("port", "SSH 포트"), ("username", "SSH 계정")):
        v = input(f"  {label} [{h.get(key)}]: ").strip()
        if v:
            h[key] = int(v) if key == "port" else v
    v = input(f"  SSH 키 파일 경로(없으면 비워둠) [{h.get('key_file', '')}]: ").strip()
    if v:
        h["key_file"] = v
    cfg["default_host"] = cfg.get("default_host") or name
    save_config(cfg)
    print(f"[nasrun] 저장: {CONFIG_PATH}")
    set_password(get_host_cfg(cfg, name))
    print("[nasrun] 접속 테스트...")
    args.sudo = True
    cmd_test(args)


def cmd_set_password(args):
    cfg = load_config() or die("[nasrun] 먼저 'python nasrun.py setup' 을 실행하세요.", 2)
    set_password(get_host_cfg(cfg, args.host))


def cmd_test(args):
    cfg = load_config() or die("[nasrun] 먼저 'python nasrun.py setup' 을 실행하세요.", 2)
    h = get_host_cfg(cfg, args.host)
    pw = get_password(h)
    client = connect(h, pw)
    rc = run_remote(client, build_remote("echo \"SSH OK: $(whoami)@$(hostname)\"", False), None, 30, pw)
    if pw:
        rc2 = run_remote(client, build_remote("echo \"SUDO OK: $(whoami)\"", True), pw + "\n", 30, pw)
        rc = rc or rc2
    client.close()
    sys.exit(rc)


def cmd_run(args):
    cfg = load_config() or die("[nasrun] 먼저 터미널에서 'python nasrun.py setup' 을 실행하세요.", 2)
    h = get_host_cfg(cfg, args.host)
    command = " ".join(args.command) if args.command else ""
    if command.strip() == "-" or not command:
        command = sys.stdin.read()
    if not command.strip():
        die("[nasrun] 실행할 명령이 없습니다.", 2)

    pw = get_password(h)
    if args.sudo and not pw:
        die("[nasrun] sudo 비밀번호가 저장돼 있지 않습니다. 사용자가 터미널에서 'python nasrun.py set-password' 를 실행해야 합니다.", 2)

    if need_confirm(h, command, args.sudo):
        if not ask_approval(h, command, args.sudo):
            log(h, command, args.sudo, "DENIED", pw)
            die("[nasrun] 사용자가 승인하지 않았습니다(거부 또는 시간 초과). 명령은 실행되지 않았습니다.", 126)

    client = connect(h, pw)
    try:
        rc = run_remote(client, build_remote(command, args.sudo),
                        (pw + "\n") if args.sudo else None, args.timeout, pw)
    finally:
        client.close()
    log(h, command, args.sudo, f"rc={rc}", pw)
    if rc != 0:
        print(f"\n[nasrun] exit code {rc}", file=sys.stderr)
    sys.exit(rc)


def main():
    p = argparse.ArgumentParser(prog="nasrun", description="AI 에이전트용 NAS·서버 SSH/sudo 브리지")
    sub = p.add_subparsers(dest="sub", required=True)

    s = sub.add_parser("setup", help="최초 설정(터미널에서 사용자가 직접)")
    s.add_argument("--host")
    s.set_defaults(func=cmd_setup)

    s = sub.add_parser("set-password", help="비밀번호 저장/변경")
    s.add_argument("--host")
    s.set_defaults(func=cmd_set_password)

    s = sub.add_parser("test", help="SSH/sudo 접속 테스트")
    s.add_argument("--host")
    s.set_defaults(func=cmd_test)

    s = sub.add_parser("run", help="원격 명령 실행")
    s.add_argument("--host")
    s.add_argument("--sudo", action="store_true", help="root 권한으로 실행")
    s.add_argument("--timeout", type=int, default=600, help="초 (기본 600, 0=무제한)")
    s.add_argument("command", nargs=argparse.REMAINDER, help="명령 문자열, '-' 이면 stdin")
    s.set_defaults(func=cmd_run)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
