# CR-link-001: 쿼리 반복 키 거부의 계약 근거

- 요청자: link(영역 통신 기반) 담당, 2026-11-08
- 받는 곳: 헤드(boundary-contracts 소유)
- 상태: 미결

## 무엇이 문제인가
`openit_link/server.py`의 `_query`는 같은 키가 둘 이상인 쿼리(`?a=1&a=2`)를 400 INVALID_RECORD("query: repeated keys")로 거부한다. 이 거부 조건은 스키마에 없고 코드에만 있다(공통 규칙 D117 위반 후보).

## 확인한 것
boundary-contracts v5.0.0의 `*.md`·`*.py`에서 "repeated"·"반복된 쿼리"·"쿼리 중복" 등을 grep했으나 쿼리 반복 키를 정하는 규칙을 찾지 못했다(`CONVENTIONS.md` 113행의 "반복 키"는 SlotRef 이야기라 무관). `HttpQueries.schema.json`이 쿼리 값을 문자열 dict로 정의하므로 반복 키는 표현할 수 없다는 암묵 전제로 보인다(추정).

## 제안(결정은 헤드)
(1) 계약 CONVENTIONS(HTTP 층 보충 규칙)에 "쿼리 키는 한 번만 쓴다. 반복되면 INVALID_RECORD(400)"를 명시하면 link 거부는 계약 근거를 얻는다. (2) 아니면 link가 반복 키를 마지막 값 등으로 받도록 바꾼다(권장하지 않음: 모호성).

link는 결정 전까지 현재 동작(400)을 유지한다.
