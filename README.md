# link — 영역 통신 기반 (D118)

영역의 통신 컴포넌트(`components/link_*`)가 쓰는 공유 라이브러리다. 헤드 소유.

## 1. 무엇을 하나
- **받는 쪽** `openit_link.server`: WSGI 앱(`App`). 경로마다 `Route(메서드, 경로 패턴, 처리 함수, roles, request_schema, response_schema, require_user)`만 적으면, 계약 HTTP 규약(boundary-contracts CONVENTIONS 6·9절)을 이 라이브러리가 지킨다: 토큰 없음·틀림 401 + `WWW-Authenticate: Bearer`, 역할 불일치 403, 사람 행위자(`X-Openit-User`) 필요 경로에서 없으면 401, 본문 상한 413(앱 판단보다 먼저), 요청을 계약 스키마로 검증(400), 2xx 응답을 응답 스키마로 검증(어기면 503, 내는 쪽 검증 R7), `BoundaryError` 본문과 고정 상태 코드, `/healthz`·`/readyz`.
- **보내는 쪽** `openit_link.clients`: 계약 패키지의 HTTP 클라이언트를 그대로 다시 내보낸다.

## 2. 의존
- boundary-contracts v3.1.1(고정). waitress로 띄우는 것은 영역의 몫(이 라이브러리는 표준 WSGI 인터페이스 PEP 3333만 쓴다).

## 3. 결정 기록
- [ADR 0001: 받는 쪽은 WSGI 앱 하나로](docs/adr/0001-받는-쪽은-WSGI-앱.md)

## 4. 개발
`bash scripts/setup-env.sh` 후 `.venv/bin/python -m pytest -q`.

## 5. 시험 상태
커밋 메시지에 새 clone + 새 venv 결과를 적는다.
