# 실행 허가

croakcode가 도구를 실행하기 직전에 게이트의 허가를 받게 한다. 게이트는 그 호출 하나에 묶인 토큰에 서명하고, 발급 기록을 남긴다. 가드레일은 모델 요청에 실린 도구 결과마다 허가가 있었는지 대조한다. 형식은 croakcode 저장소의 `docs/superpowers/architecture/2026-11-09-execution-permit-protocol.md`가 정한다.

## 무엇을 막는가

| 장치 | 막는 것 |
|---|---|
| croakcode의 허가 검증 | 정상 클라이언트가 허가 없이 도구를 실행하는 일 |
| 가드레일의 대조 | 클라이언트를 고쳐 검증을 건너뛰고 실행한 도구의 결과가 모델에 가는 일 |

대조는 도구 실행 자체를 막지 못한다. 실행은 사용자 PC에서 일어나기 때문이다. 대조가 막는 것은 그 결과가 모델의 입력이 되는 일이다.

## 구성

| 위치 | 역할 |
|---|---|
| `auth/permit_core.py` | 인자 표준 JSON과 해시, 토큰 서명, 요청 검사 |
| `auth/app.py` `POST /v1/execution-permits` | 허가 발급. Caddy가 이 경로만 로그인 서비스로 보낸다 |
| `auth/app.py` `POST /internal/permits/check` | 게이트 전용 대조 경로. Caddy는 이 경로를 밖으로 열지 않는다 |
| `auth/auth_db.py` `execution_permits` | 발급 기록. 도구 인자는 해시만 둔다. 8일이 지나면 지운다 |
| `croak_core.py` `answered_tool_calls` | 요청에서 결과가 돌아온 도구 호출을 찾는다 |
| `croak_guardrail.py` `check_permits` | 등급이 허가를 요구하면 대조한다 |
| `make-permit-key.sh` | 서명 키를 만들고 클라이언트에 줄 공개키를 출력한다 |

발급할 때는 게이트 검사와 같은 규칙을 쓴다. 접근 토큰이 유효해야 하고, 세션이 그 계정의 것이어야 하며, 등급이 그 도구를 금지하지 않아야 한다.

대조 경로는 마스터 키에서 유도한 값으로 내부 호출을 확인한다. 게이트와 로그인 서비스는 이미 마스터 키를 쓴다. 그래서 서버 `.env`에 새 비밀값이 필요 없다.

## 켜는 절차

1. 서버에서 `./make-permit-key.sh`로 서명 키를 만든다. 키는 `secrets/permit-signing.pem`(600)에 생기고, 저장소에는 올라가지 않는다.
2. 출력된 `CROAKCODE_GATE_PERMIT_PUBLIC_KEY` 값을 사용자 PC의 croakcode 설정에 넣는다. 같은 PC에 `CROAKCODE_GATE_PERMIT_URL`(게이트 주소)과 `CROAKCODE_EXECUTION_PERMIT=required`도 넣는다.
3. 모든 사용자가 2번을 마친 뒤, `policy.yaml`에서 허가를 요구할 등급에 `require_permits: true`를 넣고 배포한다.

3번을 2번보다 먼저 하면, 허가 없이 실행된 도구 결과가 대화에 남은 세션이 모두 거부된다. 대조는 대화 전체의 도구 결과를 보기 때문이다. 이런 사용자는 새 세션을 열어야 한다.

## 인자 해시

croakcode는 TypeScript로, 게이트는 Python으로 같은 인자의 해시를 만든다. 두 쪽이 같은 바이트를 만들도록 다음 규칙을 따른다.

- 모든 깊이에서 객체 키를 정렬하고 공백을 넣지 않는다.
- 정수 값인 실수는 정수로 쓴다. JavaScript는 `1.0`을 `1`로 쓰기 때문이다.
- 비ASCII 문자는 그대로 쓴다.

세 곳의 테스트가 같은 해시 표로 이 규칙을 확인한다. `auth/tests/test_permit_core.py`, `tests/test_permits.py`, croakcode의 `test/delegation/permit-parity.test.ts`다. 인자를 해석할 수 없는 호출은 어떤 허가와도 맞지 않으므로 거부된다.

## 검증

- 단위 테스트: `auth/tests/test_permit_core.py`, `tests/test_permits.py`. 가드레일 대조 테스트는 litellm이 있어야 해서, 로컬에서는 건너뛰고 E2E가 게이트 이미지 안에서 돌린다.
- E2E: `python3 tests/e2e_permits.py <작업 폴더> [croakcode의 upstream/packages/opencode 경로]`. 발급, 서명, 거부 경우, 대조, croakcode 실제 클라이언트(PT-07)를 로컬 Docker 스택에서 확인한다.
