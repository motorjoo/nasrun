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
  python nasrun.py status / revoke              # 일괄 승인 확인 / 즉시 해제
  python nasrun.py run --sudo --out db.sql.gz "pg_dump ... | gzip"   # 백업은 파일로 바로
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
GRANT_PATH = os.path.join(BASE_DIR, "nasrun_grant.json")

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
            "grant_options_min": [15, 30, 60, 120],
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


# ───────────────────────── 일괄 승인(시간제) ─────────────────────────
# 승인 창의 [일괄 승인] 버튼으로만 생성된다(생성용 CLI 없음).
# 저장된 비밀번호를 키로 HMAC 서명 → 파일을 손으로 만들거나 시간을 늘리면 무효.
def _grant_key(h, pw):
    import hashlib
    return hashlib.sha256(("nasrun-grant|" + (pw or h["hostname"])).encode("utf-8")).digest()


def _grant_mac(h, pw, expires):
    import hmac, hashlib
    msg = f"{h['username']}@{h['hostname']}|{int(expires)}".encode("utf-8")
    return hmac.new(_grant_key(h, pw), msg, hashlib.sha256).hexdigest()


def write_grant(h, pw, minutes):
    expires = int(time.time() + minutes * 60)
    data = {"target": f"{h['username']}@{h['hostname']}", "expires": expires,
            "minutes": minutes, "mac": _grant_mac(h, pw, expires)}
    with open(GRANT_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f)
    return expires


def grant_remaining(h, pw):
    """유효한 일괄 승인이 있으면 남은 초, 없으면 0."""
    import hmac
    try:
        with open(GRANT_PATH, "r", encoding="utf-8") as f:
            g = json.load(f)
        if g.get("target") != f"{h['username']}@{h['hostname']}":
            return 0
        exp = int(g["expires"])
        maxmin = max(h.get("grant_options_min") or [120])
        if not hmac.compare_digest(str(g.get("mac", "")), _grant_mac(h, pw, exp)):
            return 0
        left = exp - time.time()
        if left <= 0 or left > maxmin * 60 + 5:
            return 0
        return int(left)
    except Exception:
        return 0


def revoke_grant():
    if os.path.exists(GRANT_PATH):
        os.remove(GRANT_PATH)
        return True
    return False


def ask_approval(h, cmd, sudo):
    """PC 화면에 승인 창. 반환: False=거부/시간초과, "once"=이것만, int(분)=일괄 승인."""
    timeout = int(h.get("confirm_timeout_sec", 120))
    try:
        import tkinter as tk
    except Exception:
        print("[nasrun] tkinter 사용 불가 → 승인 창을 띄울 수 없어 거부합니다.", file=sys.stderr)
        return False

    result = {"ok": False}
    opts = [int(m) for m in (h.get("grant_options_min") or [15, 30, 60, 120])]
    try:
        root = tk.Tk()
    except Exception as e:
        print(f"[nasrun] 승인 창 생성 실패({e}) → 거부합니다.", file=sys.stderr)
        return False

    root.title("nasrun — NAS 명령 승인")
    root.attributes("-topmost", True)
    # 주 모니터 정중앙에 띄운다(사용자 요청 2026-10-24).
    w, hgt = 760, 420
    x = max(0, (root.winfo_screenwidth() - w) // 2)
    y = max(0, (root.winfo_screenheight() - hgt) // 2)
    root.geometry(f"{w}x{hgt}+{x}+{y}")
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
        result["ok"] = "once"
        root.destroy()

    def approve_all(_=None):
        try:
            result["ok"] = int(str(gvar.get()).replace("분", "").strip())
        except Exception:
            result["ok"] = opts[min(1, len(opts) - 1)]
        root.destroy()

    def deny(_=None):
        result["ok"] = False
        root.destroy()

    gvar = tk.StringVar(value=f"{opts[min(1, len(opts) - 1)]}분")
    tk.Button(bar, text="일괄 승인", width=10, command=approve_all, bg="#0d47a1", fg="white").pack(side="right", padx=(2, 4))
    tk.OptionMenu(bar, gvar, *[f"{m}분" for m in opts]).pack(side="right")
    tk.Label(bar, text="  |  ", fg="#999").pack(side="right")
    tk.Button(bar, text="이것만 승인 (Enter)", width=16, command=approve, bg="#1b5e20", fg="white").pack(side="right", padx=4)
    tk.Button(bar, text="거부 (Esc)", width=10, command=deny).pack(side="right", padx=4)
    tk.Label(root, text="일괄 승인: 선택한 시간 동안 이후 sudo 명령을 창 없이 실행합니다. 끄기: python nasrun.py revoke",
             font=("Malgun Gothic", 9), fg="#0d47a1").pack(anchor="w", padx=12, pady=(0, 8))
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
              timeout=20, banner_timeout=60, auth_timeout=60,
              allow_agent=False, look_for_keys=False)
    key_file = os.path.expanduser(h.get("key_file") or "")
    if key_file and os.path.exists(key_file):
        kw["key_filename"] = key_file
    elif password:
        kw["password"] = password
    else:
        die("[nasrun] 로그인 수단이 없습니다. 'python nasrun.py set-password' 로 비밀번호를 저장하거나 key_file 을 설정하세요.", 2)
    # 유휴 상태의 NAS(디스크 절전/Tailscale 대기)는 첫 로그인이 느려
    # 'Authentication timeout' / 'No existing session' 이 일시적으로 날 수 있음 → 1회 재시도
    for attempt in (1, 2):
        try:
            client.connect(**kw)
            break
        except paramiko.BadHostKeyException:
            die("[nasrun] NAS 호스트 키가 바뀌었습니다! 의도한 변경이면 nasrun_known_hosts 에서 해당 줄을 지우세요.", 3)
        except paramiko.AuthenticationException as e:
            msg = str(e)
            if attempt == 1 and "timeout" in msg.lower():
                print(f"[nasrun] 로그인 지연({msg}) — 3초 후 재시도", file=sys.stderr)
                client.close(); time.sleep(3); continue
            die(f"[nasrun] SSH 인증 실패: {msg} (아이디/비밀번호/키 확인)", 3)
        except (socket.error, paramiko.SSHException, EOFError) as e:
            if attempt == 1:
                print(f"[nasrun] 접속 일시 실패({e}) — 3초 후 재시도", file=sys.stderr)
                client.close(); time.sleep(3); continue
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


def run_remote(client, remote, stdin_data, timeout, secret, out_path=None):
    """원격 실행. stdout/stderr 를 '바이트 그대로' 전달하고, 채널 EOF 까지 끝까지 읽는다.

    주의: sshd 는 exit-status 를 남은 출력보다 먼저 보낼 수 있다(지연 큰 회선에서 흔함).
    exit_status_ready() 로 루프를 끝내면 출력 끝부분이 잘린다 → 반드시 EOF 기준으로 종료.
    """
    chan = client.get_transport().open_session()
    chan.settimeout(1.0)
    chan.exec_command(remote)
    if stdin_data is not None:
        chan.sendall(stdin_data.encode("utf-8"))
    chan.shutdown_write()

    out_fh = open(out_path, "wb") if out_path else None
    import hashlib
    sha = hashlib.sha256()
    # --out 파일은 원본 그대로(마스킹 안 함), 화면 출력만 마스킹
    out_sink = _Sink(out_fh, None, sha) if out_fh else _Sink(_bin(sys.stdout), secret, None)
    err_sink = _Sink(_bin(sys.stderr), secret, None)
    start = time.time()
    rc = None
    try:
        while True:
            got = False
            while chan.recv_ready():
                out_sink.write(chan.recv(1 << 20))
                got = True
            while chan.recv_stderr_ready():
                err_sink.write(chan.recv_stderr(1 << 20))
                got = True
            if (chan.eof_received or chan.closed) and not chan.recv_ready() and not chan.recv_stderr_ready():
                break
            if timeout and time.time() - start > timeout:
                chan.close()
                err_sink.write(f"\n[nasrun] 시간 초과({timeout}s) — 원격 명령을 끊었습니다.\n".encode("utf-8"))
                rc = 124
                break
            if not got:
                time.sleep(0.02)
        if rc is None:
            # EOF 이후 exit-status 가 늦게 올 수 있음 → 잠시 대기
            deadline = time.time() + 30
            while not chan.exit_status_ready() and time.time() < deadline:
                time.sleep(0.02)
            rc = chan.recv_exit_status() if chan.exit_status_ready() else 255
    finally:
        out_sink.flush()
        err_sink.flush()
        if out_fh:
            out_fh.close()
    if out_path:
        print(f"[nasrun] saved {out_sink.count} bytes -> {out_path}  sha256={sha.hexdigest()}", file=sys.stderr)
    return rc


def _bin(stream):
    """텍스트 변환/CRLF 치환 없이 쓰는 바이너리 스트림."""
    stream.flush()
    return getattr(stream, "buffer", stream)


class _Sink:
    """바이트 그대로 출력. secret 이 청크 경계에 걸쳐도 마스킹되도록 꼬리 버퍼 유지."""
    def __init__(self, fh, secret, sha):
        self.fh = fh
        self.sec = secret.encode("utf-8") if secret else b""
        self.keep = max(len(self.sec) - 1, 0)
        self.buf = b""
        self.sha = sha
        self.count = 0

    def _emit(self, data):
        if not data:
            return
        self.fh.write(data)
        self.count += len(data)
        if self.sha:
            self.sha.update(data)

    def write(self, data):
        if not data:
            return
        if not self.sec:
            self._emit(data)
            return
        self.buf = (self.buf + data).replace(self.sec, b"****")
        if len(self.buf) > self.keep:
            cut = len(self.buf) - self.keep
            self._emit(self.buf[:cut])
            self.buf = self.buf[cut:]

    def flush(self):
        if self.buf:
            self._emit(self.buf.replace(self.sec, b"****") if self.sec else self.buf)
            self.buf = b""
        try:
            self.fh.flush()
        except Exception:
            pass


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
        left = grant_remaining(h, pw)
        if left:
            print(f"[nasrun] 일괄 승인 적용 중 — 남은 시간 {left // 60}분 {left % 60}초", file=sys.stderr)
            log(h, command, args.sudo, "GRANT", pw)
        else:
            ans = ask_approval(h, command, args.sudo)
            if not ans:
                log(h, command, args.sudo, "DENIED", pw)
                die("[nasrun] 사용자가 승인하지 않았습니다(거부 또는 시간 초과). 명령은 실행되지 않았습니다.", 126)
            if isinstance(ans, int) and not isinstance(ans, bool):
                exp = write_grant(h, pw, ans)
                until = datetime.datetime.fromtimestamp(exp).strftime("%H:%M")
                print(f"[nasrun] 일괄 승인 시작 — {ans}분({until}까지) 동안 sudo 명령 자동 승인", file=sys.stderr)
                log(h, f"(일괄 승인 {ans}분, ~{until}) " + command, args.sudo, "GRANT-START", pw)

    client = connect(h, pw)
    try:
        rc = run_remote(client, build_remote(command, args.sudo),
                        (pw + "\n") if args.sudo else None, args.timeout, pw, args.out)
    finally:
        client.close()
    log(h, command, args.sudo, f"rc={rc}", pw)
    if rc != 0:
        print(f"\n[nasrun] exit code {rc}", file=sys.stderr)
    sys.exit(rc)


def cmd_revoke(args):
    print("[nasrun] 일괄 승인을 해제했습니다." if revoke_grant() else "[nasrun] 활성화된 일괄 승인이 없습니다.")


def cmd_status(args):
    cfg = load_config() or die("[nasrun] 먼저 'python nasrun.py setup' 을 실행하세요.", 2)
    h = get_host_cfg(cfg, args.host)
    left = grant_remaining(h, get_password(h))
    if left:
        print(f"[nasrun] 일괄 승인 활성 — 남은 시간 {left // 60}분 {left % 60}초")
    else:
        print(f"[nasrun] 일괄 승인 없음 (confirm={h.get('confirm')})")


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

    s = sub.add_parser("revoke", help="일괄 승인 즉시 해제")
    s.set_defaults(func=cmd_revoke)

    s = sub.add_parser("status", help="일괄 승인 남은 시간 확인")
    s.add_argument("--host")
    s.set_defaults(func=cmd_status)

    s = sub.add_parser("run", help="원격 명령 실행")
    s.add_argument("--host")
    s.add_argument("--sudo", action="store_true", help="root 권한으로 실행")
    s.add_argument("--timeout", type=int, default=600, help="초 (기본 600, 0=무제한)")
    s.add_argument("--out", help="stdout 을 이 파일에 원본 그대로 저장(백업/바이너리용), 바이트수·sha256 출력")
    s.add_argument("command", nargs=argparse.REMAINDER, help="명령 문자열, '-' 이면 stdin")
    s.set_defaults(func=cmd_run)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
