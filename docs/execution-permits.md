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
2. `policy.yaml`에서 허가를 요구할 등급에 `require_permits: true`를 넣고 배포한다.

사용자 PC에는 따로 설정할 것이 없다. 로그인 서비스는 로그인과 토큰 갱신 응답에 `execution_permits`를 넣는다. 값은 그 계정 등급이 허가를 요구하는지(`required`)와 허가를 확인할 공개키(`public_key`)다. croakcode는 이 값을 로그인 정보와 함께 저장하고, 그 값에 따라 허가 검증을 한다. `/auth/me`도 같은 값을 돌려준다.

이미 로그인한 PC는 다음 토큰 갱신 때 새 값을 받는다. 접근 토큰은 한 시간마다 갱신된다. 그 사이에 허가 없이 실행한 도구 결과가 대화에 남은 세션은 거부된다. 대조는 대화 전체의 도구 결과를 보기 때문이다. 이런 사용자는 새 세션을 열어야 한다.

croakcode의 환경 변수 `CROAKCODE_EXECUTION_PERMIT`는 로그인 값보다 먼저 적용된다. 시험이나 수동 설정에만 쓴다.

## 대리 호출 도구

croakcode는 실험 기능 `deferred_tools`를 켜면 대부분의 도구를 `tool_call {"name": <도구>, "input": <인자>}`로 부른다. croakcode는 안쪽 도구의 이름과 인자로 허가를 받는다. 그래서 대조도 `tool_call` 결과를 안쪽 도구로 본다(`croak_core.py` `TOOL_PROXY`). `tool_call` 이름으로는 허가를 발급하지 않는다. 그렇게 하면 등급이 막은 도구를 감싸 부를 수 있다.

## 인자 해시

croakcode는 TypeScript로, 게이트는 Python으로 같은 인자의 해시를 만든다. 두 쪽이 같은 바이트를 만들도록 다음 규칙을 따른다.

- 모든 깊이에서 객체 키를 정렬하고 공백을 넣지 않는다.
- 정수 값인 실수는 정수로 쓴다. JavaScript는 `1.0`을 `1`로 쓰기 때문이다.
- 비ASCII 문자는 그대로 쓴다.

세 곳의 테스트가 같은 해시 표로 이 규칙을 확인한다. `auth/tests/test_permit_core.py`, `tests/test_permits.py`, croakcode의 `test/delegation/permit-parity.test.ts`다. 인자를 해석할 수 없는 호출은 어떤 허가와도 맞지 않으므로 거부된다.

## 대조하는 도구 결과

게이트는 요청에 실린 대화 기록 전체의 도구 결과를 대조한다. 새로 실행한 도구만 보지 않는다. 2026-11-12에 운영에서 `require_permits`를 두 번 켰고, 두 번 모두 허가 없는 결과 때문에 세션이 거부됐다. 그때 찾은 경로와 지금의 규칙을 적는다.

| 경로 | 처리 |
|---|---|
| 모델이 부른 도구 | croakcode가 실행 전에 허가를 받는다 |
| 허가 전에 끝난 호출 | croakcode가 결과를 정해진 문장으로 바꿔 보낸다. 게이트는 그 문장만 허가 없이 받는다 |
| `tool_search` | 실행 전에 허가를 받는다 |
| 사용자가 직접 실행한 셸(`!명령`) | `bash` 허가를 받는다. 받지 못하면 실행하지 않는다 |
| 사용자가 부른 하위 작업 | `task` 허가를 받는다 |
| 구조화된 출력 도구 | `StructuredOutput` 허가를 받는다 |
| 복제한 세션의 복사된 호출 | 복제 세션이 첫 요청 전에 호출마다 허가를 다시 받는다 |

- 허가 전에 끝난 호출은 정책 플러그인이 막은 호출 같은 경우다. 정해진 문장은 `croak_core.UNRUN_RESULT`와 croakcode의 `Permit.UNRUN_RESULT`가 같아야 한다. 글자가 하나라도 다르면 허가가 필요하다. 문장이 고정이라 그 통로로는 실행 결과를 내보낼 수 없다.
- 허가는 다른 세션으로 넘어가지 않는다. 복제한 세션도 예외가 아니다. 그래서 croakcode가 새 세션 이름으로 다시 받는다.
- 허가 기록은 90일 동안 둔다(`CROAK_PERMIT_KEEP_DAYS`). 대화는 로그인 세션보다 오래 이어지고, 게이트는 요청마다 예전 도구 결과도 대조한다. 처음에는 8일이었다. 8일이 지난 대화는 모두 거부될 값이었다. 90일이 지난 대화는 새 세션에서 다시 시작한다.

## 검증

- 단위 테스트: `auth/tests/test_permit_core.py`, `tests/test_permits.py`. 가드레일 대조 테스트는 litellm이 있어야 해서, 로컬에서는 건너뛰고 E2E가 게이트 이미지 안에서 돌린다.
- E2E: `python3 tests/e2e_permits.py <작업 폴더> [croakcode의 upstream/packages/opencode 경로]`. 로컬 Docker 스택에서 발급, 서명, 거부 경우, 대조를 확인한다. croakcode 경로를 주면 실제 클라이언트(PT-07), 허가 필수 상태의 한 턴(PT-08), 로그인만으로 켜지는 허가(PT-09)도 확인한다. PT-08은 가짜 모델의 `CALL_TOOL` 지시로 `tool_call`을 부른다. PT-10은 `read` 직접 호출, PT-11은 허가 전에 막힌 호출, PT-12는 `tool_search`, PT-13은 세션 복제를 확인한다.
