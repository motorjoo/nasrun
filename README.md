# nasrun

**Let your AI coding agent run `sudo` on your NAS / Linux server — without ever seeing your password.**
**AI 코딩 에이전트가 NAS·서버에서 sudo 명령을 직접 실행하고 결과를 받게 해 주는 브리지. 비밀번호는 AI에게 절대 노출되지 않습니다.**

Works with any agent that can run a shell command: **Claude Code, OpenAI Codex CLI, Cursor, Gemini CLI, Aider…**

---

## 왜 만들었나 / Why

AI 에이전트의 셸은 비대화형이라 `sudo` 비밀번호 프롬프트에서 멈춥니다.
그래서 지금까지는 **명령 복사 → 터미널에 붙여넣기 → 비밀번호 입력 → 결과 복사 → 다시 AI에 붙여넣기**를 사람이 반복해야 했습니다.

nasrun은 이 중계를 없앱니다.

Agent shells are non-interactive, so `sudo` password prompts break them. The usual workaround is a human copy-paste relay. nasrun removes the human from that loop **without** handing the password to the AI.

```
AI agent ──► python nasrun.py run --sudo "docker compose up -d"
                │
                ├─ password  : OS keychain (Windows Credential Manager / macOS Keychain / Secret Service)
                ├─ approval  : desktop popup for sudo commands — you click Approve (auto-deny after 120 s)
                ├─ transport : SSH (paramiko), password piped to `sudo -k -S` via stdin only
                └─ result    : remote stdout / stderr / exit code returned as-is → agent reads it directly
```

## 특징 / Features
- 🔐 **비밀번호 비노출** — OS 키체인에 저장, 명령줄·로그·AI 컨텍스트 어디에도 안 나옴. 출력에 섞여도 `****` 마스킹
- ✅ **사람 승인** — sudo 명령은 데스크톱 승인 창. 조회 명령(`docker ps`, `ls`, `df` …)은 정규식 화이트리스트로 자동 통과. `; | & $ \` < >`나 줄바꿈이 섞이면 무조건 승인 창
- 🧱 **안전한 sudo 처리** — `sudo -k`로 매번 재인증, 실행 명령의 stdin은 `/dev/null`로 차단(비밀번호를 읽을 수 없음)
- 🔑 **호스트 키 고정(TOFU)** — 최초 접속 키 저장, 바뀌면 접속 거부
- 📜 **감사 로그** — 모든 실행/거부 기록
- 🐳 **Synology 친화** — 비대화형 SSH에서 빠지는 `/usr/local/bin`(docker 등) PATH 자동 보정
- 📦 **출력 무결성** — 채널 EOF까지 끝까지 수신(종료 신호 뒤에 오는 출력도 놓치지 않음), 바이트 그대로 전달(CRLF 변환 없음), `--out`으로 파일 저장 + sha256
- 🖥️ 여러 대 서버 등록(`--host`), 타임아웃, 여러 줄 스크립트(stdin), 원격 종료코드 그대로 반환

## 설치 / Install
```bash
pip install paramiko keyring
python nasrun.py setup        # 주소·포트·계정 입력 + 비밀번호를 키체인에 저장 + 접속 테스트
```
Windows는 `install.bat` 더블클릭으로도 가능. 서버 쪽은 SSH 활성화 + sudo 가능한 계정이면 됩니다 (Synology: 제어판 → 터미널 및 SNMP → SSH 활성화, administrators 그룹 계정).

## 사용 / Usage
```bash
python nasrun.py run "df -h"
python nasrun.py run --sudo "docker ps -a"
python nasrun.py run --sudo --timeout 1800 "docker compose -f /volume1/docker/app/docker-compose.yml up -d"
python nasrun.py run --sudo - < deploy.sh        # multi-line script via stdin
python nasrun.py run --sudo --out db.dump "cat /volume1/backup/db.dump"   # big/binary output -> file (prints bytes + sha256)
python nasrun.py test
python nasrun.py set-password                    # after changing the server password
```

## AI 에이전트에 알려주기 / Tell your agent
`CLAUDE.md.snippet`의 내용을 에이전트의 규칙 파일에 붙여 넣으세요 (경로만 본인 환경에 맞게 수정).

| Agent | 규칙 파일 |
|---|---|
| Claude Code | `CLAUDE.md` 또는 `~/.claude/CLAUDE.md` |
| OpenAI Codex CLI | `AGENTS.md` 또는 `~/.codex/AGENTS.md` |
| Gemini CLI | `GEMINI.md` |
| Cursor | `.cursor/rules/` |

## 설정 / Config (`nasrun.json`, git 제외)
| key | 의미 |
|---|---|
| `confirm` | `sudo`(기본) / `always` / `never` |
| `auto_approve` | 승인 없이 통과시킬 정규식 목록 |
| `confirm_timeout_sec` | 승인 창 자동 거부 시간 (기본 120) |
| `key_file` | SSH 키 경로 (있으면 키 로그인, sudo 비밀번호는 키체인) |
| `hosts` | 서버 여러 대 → `--host 이름` |

예시: `nasrun.example.json`

## 종료코드 / Exit codes
원격 명령 rc 그대로 · `2` config · `3` SSH/auth/host-key · `124` timeout · `126` denied by user

## 보안 메모 / Security notes
- 승인 창을 끄면(`confirm: never`) AI가 root 명령을 자유롭게 실행할 수 있습니다. 화이트리스트는 좁게 유지하세요.
- AI가 `nasrun.json`을 고쳐 승인 설정을 풀 수 있으니, 규칙 파일에 "수정 금지"를 명시하세요 (snippet에 포함).
- Tested: Windows 11 + Python 3.14 → Synology DSM 7 (via Tailscale), Ubuntu OpenSSH.

## License
MIT — made by **HWAYOUNGSYSTEMS (PARA)**, Gimhae, Korea.
