# Croak

로컬 LLM 앞에 두는 게이트다. 모델로 가는 요청을 사용자 등급에 따라 검사한다. 비밀정보가 있으면 요청을 막고, 개인정보는 가린 뒤 보낸다. 모든 요청은 기록으로 남는다. 로그인 서비스와 관리 화면도 이 저장소에 있다.

CodeFrog 그룹의 서버 쪽 저장소다. 클라이언트(opencode 패치, 설정, 플러그인)는 [`codefrog/opencode`](../opencode)에 있다.

| 폴더 | 내용 |
|---|---|
| `gateway/` | LiteLLM 설정, 가드레일, 정책, Compose, 배포 스크립트 |
| `gateway/auth/` | 로그인 서비스와 관리 화면 (FastAPI) |
| `gateway/ocr/` | 이미지와 PDF의 글자를 읽는 OCR 서비스 (Tesseract 한국어, 영어) |
| `gateway/tls/` | 내부 인증 기관과 서버 인증서를 만드는 스크립트 |
| `gateway/tests/` | 단위 테스트와 e2e 테스트 |
| `bench/` | OpenAI 호환 API 스트리밍 벤치마크와 결과 |
| `docs/` | 설계 문서. 로그인과 권한은 `auth.md` |

## 구성

```
opencode ──HTTPS──▶ gate:8443 Caddy ─┬─▶ /v1/*                  croak-gate (LiteLLM + 가드레일)
                                    └─▶ /, /auth/*, /admin/*   croak-auth (로그인, 관리 화면)
```

| 서비스 | 하는 일 |
|---|---|
| `proxy` | Caddy. TLS를 맡고 경로별로 넘긴다. LiteLLM 관리 경로는 밖에서 닿지 않는다 |
| `gate` | LiteLLM. 키를 검사하고 상위 LiteLLM으로 요청을 넘긴다. `croak_guardrail.py`가 등급, 에이전트, 도구, 비밀정보, 개인정보를 검사한다 |
| `auth` | 로그인 페이지, 확인 코드, 토큰 발급과 갱신, 관리 화면 |
| `db` | Postgres. 게이트 DB(`croak_gate`)와 로그인 DB(`croak_auth`) |
| `ocr` | 이미지와 PDF의 글자를 읽어 같은 규칙으로 검사한다. 이미지는 걸린 글자 위에 검은 상자를 칠하고, PDF는 가린 텍스트로 바꾼다. 원본은 보관 기록에 남기지 않는다 |

## 배포

```bash
cd gateway
./tls/make-certs.sh          # 처음 한 번: 내부 인증 기관과 서버 인증서
./deploy.sh --diff           # 서버와 다른 점만 본다
./deploy.sh                  # 테스트, 차이 확인, 백업, 업로드, 재시작, 상태 확인. 실패하면 되돌린다
```

서버는 `user@gate.example.internal:~/croak`이다. 서버의 `.env`(600)는 올리지도 출력하지도 않는다. 형식은 `.env.example`에 있다.

| 스크립트 | 용도 |
|---|---|
| `set-key-tier.sh` | 기존 게이트 키에 등급을 붙인다 |
| `issue-key.sh` | 로그인 없이 쓰는 키를 발급한다. 일반 사용자는 `/login`을 쓴다 |
| `purge-secret-archive.sh` | 규칙이 생기기 전에 저장된 비밀정보 기록을 지운다 |
| `remask-archive.sh` | 규칙이 생기기 전에 저장된 기록의 비밀정보와 개인정보를 다시 가린다 |
| `auth/cli.py` | 서버에서 계정을 관리한다. 관리 화면의 사용자 메뉴와 같은 일을 한다 |

## 클라이언트 계약

opencode 플러그인과 이 게이트가 함께 지키는 약속이다. 한쪽만 바꿀 때 이 표를 깨지 않는지 확인한다.

| 항목 | 값 |
|---|---|
| 요청 머리글 | `x-croak-agent`(에이전트 이름), `x-croak-session`(opencode 세션 ID) |
| 인증 | `Authorization: Bearer <접근 토큰>`. 접근 토큰은 로그인 서비스가 발급한 게이트 키다 |
| 로그인 API | `GET /auth/login?challenge=`, `POST /auth/token`, `POST /auth/logout`, `GET /auth/me` |
| 키 메타데이터 | `croak_user`, `croak_tier`, `croak_roles`, `croak_session` |
| 오류 문구 | 게이트가 거부하면 메시지가 `[croak]`로 시작한다 |

자세한 흐름과 등급 규칙은 `docs/auth.md`에 있다.

## 테스트

```bash
cd gateway
python3 -m unittest tests/test_core.py tests/test_store.py auth/tests/test_auth_core.py auth/tests/test_admin_core.py
python3 tests/e2e.py <작업 폴더>     # Docker로 전체 스택을 띄워 확인한다
```

## 비밀정보

API 키, 비밀번호, 인증서 개인 키는 이 저장소에 넣지 않는다. 서버의 `.env`와 각 PC의 600 권한 파일에만 둔다.
