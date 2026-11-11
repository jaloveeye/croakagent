# 모델 등록부

`gateway/models.yaml`은 모델 정보를 두는 단 하나의 곳이다. 게이트 뒤의 서빙 엔진과 모델이 바뀌어도 클라이언트 설정은 바꾸지 않는다. 바꾸는 것은 이 파일이다.

## 무엇을 적나

| 항목 | 뜻 |
|---|---|
| `upstream_defaults` | 모든 별칭에 공통인 뒤쪽 LiteLLM 주소, 키, 시간 제한 |
| `models.<별칭>.display` | 클라이언트 화면 이름 |
| `models.<별칭>.listed` | 클라이언트 모델 목록에 보일지. 예전 별칭은 `false` |
| `models.<별칭>.served_model` | 실제로 서빙하는 모델. 기록에만 쓰고 사용자에게 보이지 않는다 |
| `models.<별칭>.engine` | `vllm`, `sglang`, `llamacpp`, `tensorfold`, `unknown` |
| `models.<별칭>.upstream` | 뒤쪽 LiteLLM이 아는 이름(`model`)과 기본값을 바꿀 항목 |
| `models.<별칭>.limits` | `context`, `output` 토큰 한도 |
| `models.<별칭>.reasoning` | 추론 수준 `none`, `low`, `high`마다 요청에 더할 값과 기본 수준 |

추론 수준은 모델 고유의 방식(채팅 템플릿 인자 등)으로 적는다. 토큰 예산으로 수준을 흉내 내지 않는다. 예산이 필요하면 `max_reasoning_tokens`에 안전 상한으로만 둔다.

## 어디에 쓰이나

- `make_config.py`가 등록부와 `config.base.yaml`로 LiteLLM의 `config.yaml`을 만든다. 저장소의 `config.yaml`은 저장소 등록부로 만든 결과다. `tests/test_models.py`가 둘이 같은지 확인한다.
- `deploy.sh`는 `CROAK_MODELS_FILE`(기본 `models.yaml`)로 `config.yaml`을 만들어 올린다. 등록부 파일도 함께 올린다.
- 추론 수준 변환, 요청 기록, 클라이언트 모델 목록은 다음 작업에서 이 등록부를 쓴다.

## 운영 등록부

저장소의 등록부에는 지금 별칭과 자리 표시 값만 있다. 실제 모델과 엔진을 적은 운영 등록부는 `gateway/local/models.yaml`에 두고 저장소에 올리지 않는다.

```
CROAK_POLICY_FILE=local/policy.yaml CROAK_MODELS_FILE=local/models.yaml ./deploy.sh
```

엔진이나 모델을 바꾸면 추론 수준 값을 다시 확인한다. 같은 질문을 수준마다 보내 추론 토큰과 답을 비교한다.
