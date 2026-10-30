"""영역 통신의 받는 쪽 기반(D118): 계약 HTTP 규약(CONVENTIONS 6·9절)을 한 곳에서 지키는 WSGI 앱.

영역의 받는 쪽 통신 컴포넌트(`link_*`)는 경로마다 Route(메서드, 경로 패턴, 요청 스키마, 응답 스키마, 허용 역할, 사람 머리글 필요 여부, 처리 함수)만 적는다.
이 모듈이 하는 일: 토큰 → 역할(없거나 틀리면 401 + WWW-Authenticate, 역할이 맞지 않으면 403), `X-Openit-User`(필요한 경로에서 없으면 401),
본문 상한(413), JSON 해석, 요청을 계약 스키마로 검증(400 INVALID_RECORD), 처리 함수가 낸 값을 응답 스키마로 검증(내는 쪽 검증, R7),
`BoundaryError` → 상태 코드(CONVENTIONS 9절 표), `/healthz`·`/readyz`.
왜 WSGI: 영역 서버가 모두 waitress(WSGI) 위에서 돈다(2026-10-30 확인). 프레임워크를 새로 들이지 않고 표준 인터페이스(PEP 3333)만 쓴다.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional

from boundary_contracts import PIPELINE_SCHEMA_VERSION, BoundaryError, validator

# CONVENTIONS 9절의 고정 표. 401은 PERMISSION_DENIED + details.http_status 401로 낸다(D106).
STATUS = {"INVALID_RECORD": 400, "PERMISSION_DENIED": 403, "NOT_FOUND": 404, "CONFLICT": 409,
          "FAILED_PRECONDITION": 412, "UNSUPPORTED_VERSION": 422, "INTEGRITY_ERROR": 422, "UNAVAILABLE": 503}
REASON = {200: "OK", 201: "Created", 202: "Accepted", 204: "No Content", 400: "Bad Request", 401: "Unauthorized",
          403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed", 409: "Conflict", 412: "Precondition Failed",
          413: "Content Too Large", 422: "Unprocessable Content", 503: "Service Unavailable"}
DEFAULT_MAX_BODY = 1 * 2**20   # 1 MiB: 계약 요청 본문(레코드 하나)의 상한. 측정값이 아니라 판단이다. 큰 본문(패키지 tar)을 받는 경로는 Route.max_body로 늘린다


@dataclass(frozen=True)
class Request:
    """처리 함수가 받는 것. body는 요청 스키마 검증을 통과한 값(없으면 None), params는 경로의 이름 붙은 조각."""
    method: str
    path: str
    params: Mapping[str, str]
    query: Mapping[str, str]
    body: Any
    raw: bytes
    role: Optional[str]
    user: Optional[str]
    headers: Mapping[str, str]


@dataclass(frozen=True)
class Response:
    status: int
    body: Any = None                       # dict·list면 JSON, str이면 text/plain, bytes면 그대로
    headers: Mapping[str, str] = field(default_factory=dict)
    content_type: Optional[str] = None


@dataclass(frozen=True)
class Route:
    method: str
    pattern: str                           # 예: "/v1/cases/{case_id}/review"
    handler: Callable[[Request], Response]
    roles: frozenset = frozenset()         # 빈 집합이면 인증 없음(공개 경로)
    request_schema: Optional[str] = None   # 계약 스키마 이름. JSON 본문을 이것으로 검증한다
    response_schema: Optional[str] = None  # 2xx JSON 본문을 이것으로 검증한다(내는 쪽 검증)
    require_user: bool = False             # 사람 행위자(X-Openit-User)가 필요한 쓰기
    raw_body: bool = False                 # JSON이 아닌 본문(tar 등)을 그대로 넘긴다
    max_body: int = DEFAULT_MAX_BODY

    def compiled(self):
        rx = "^" + re.sub(r"\\\{(\w+)\\\}", r"(?P<\1>[^/]+)", re.escape(self.pattern)) + "$"
        return re.compile(rx)


def _unauth(message: str) -> BoundaryError:
    return BoundaryError("PERMISSION_DENIED", message, {"http_status": 401})


class App:
    """WSGI 앱. tokens: 토큰 문자열 → 역할 이름(비밀은 파일에서 읽어 넘긴다, D84). ready: /readyz 판정 함수 → (준비됨, 본문 dict)."""

    def __init__(self, routes: list[Route], tokens: Mapping[str, str], *, ready: Optional[Callable[[], tuple]] = None,
                 user_header_trusted: bool = True):
        self._routes = [(r, r.compiled()) for r in routes]
        self._tokens = dict(tokens)
        self._ready = ready
        self._user_trusted = user_header_trusted   # 게이트웨이 뒤 내부망에서만 X-Openit-User를 믿는다(게이트웨이가 덮어쓴다, D88)

    # ---- WSGI ----
    def __call__(self, environ, start_response):
        status, headers, body = self.handle(environ)
        start_response(f"{status} {REASON.get(status, '')}".strip(), list(headers.items()))
        return [body]

    def handle(self, environ) -> tuple:
        method = environ.get("REQUEST_METHOD", "GET").upper()
        path = environ.get("PATH_INFO", "/")
        try:
            if path == "/healthz" and method == "GET":
                return self._json(200, {"status": "ok"})
            if path == "/readyz" and method == "GET":
                ok, info = self._ready() if self._ready else (True, {"status": "ready"})
                return self._json(200 if ok else 503, info)
            route, params = self._match(method, path)
            raw = self._read(environ, route.max_body)   # 전송 한도(413)는 앱 판단보다 먼저다(CONVENTIONS 9절 2.2.2: HTTP 서버가 앱을 부르기 전에 낸다)
            role = self._auth(route, environ)
            user = environ.get("HTTP_X_OPENIT_USER") if self._user_trusted else None
            if route.require_user and not user:
                raise _unauth("사람 행위자(X-Openit-User)가 없다")
            body = None
            if raw and not route.raw_body:
                try:
                    body = json.loads(raw)
                except ValueError:
                    raise BoundaryError("INVALID_RECORD", "본문이 JSON이 아니다") from None
            if route.request_schema is not None:
                errs = [e.message for e in validator(route.request_schema).iter_errors(body)]
                if errs:
                    raise BoundaryError("INVALID_RECORD", f"{route.request_schema} 위반: {errs[0][:200]}")
            req = Request(method, path, params, _query(environ), body, raw, role, user, _headers(environ))
            resp = route.handler(req)
            if route.response_schema is not None and 200 <= resp.status < 300 and isinstance(resp.body, (dict, list)):
                errs = [e.message for e in validator(route.response_schema).iter_errors(resp.body)]
                if errs:   # 내는 쪽이 계약을 어기면 받는 쪽에 틀린 값을 보내지 않는다: 서버 결함
                    raise BoundaryError("UNAVAILABLE", f"응답이 {route.response_schema}를 어긴다(서버 결함)")
            return self._out(resp)
        except BoundaryError as e:
            return self._error(e)
        except _HttpOnly as e:
            return e.status, {"Content-Type": "application/json"}, json.dumps({"message": e.message}).encode()

    # ---- 내부 ----
    def _match(self, method: str, path: str):
        allowed = False
        for r, rx in self._routes:
            m = rx.match(path)
            if m:
                if r.method == method:
                    return r, m.groupdict()
                allowed = True
        if allowed:
            raise _HttpOnly(405, "허용하지 않는 메서드")
        raise BoundaryError("NOT_FOUND", "경로가 없다")

    def _auth(self, route: Route, environ) -> Optional[str]:
        if not route.roles:
            return None
        auth = environ.get("HTTP_AUTHORIZATION", "")
        role = self._tokens.get(auth[7:]) if auth.startswith("Bearer ") else None
        if role is None:
            raise _unauth("토큰이 없거나 틀리다")
        if role not in route.roles:
            raise BoundaryError("PERMISSION_DENIED", "이 호출을 할 권한이 없다")
        return role

    @staticmethod
    def _read(environ, limit: int) -> bytes:
        try:
            n = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            raise BoundaryError("INVALID_RECORD", "Content-Length가 잘못됐다") from None
        if n > limit:
            raise _HttpOnly(413, f"본문이 상한({limit}바이트)을 넘는다")
        return environ["wsgi.input"].read(n) if n else b""

    @staticmethod
    def _json(status: int, obj) -> tuple:
        return status, {"Content-Type": "application/json", "Cache-Control": "no-store"}, json.dumps(obj, ensure_ascii=False).encode()

    def _out(self, resp: Response) -> tuple:
        b = resp.body
        if isinstance(b, (dict, list)):
            status, headers, data = self._json(resp.status, b)
        elif isinstance(b, str):
            status, headers, data = resp.status, {"Content-Type": "text/plain; charset=utf-8"}, b.encode()
        else:
            status, headers, data = resp.status, {"Content-Type": resp.content_type or "application/octet-stream"}, b or b""
        if resp.content_type:
            headers["Content-Type"] = resp.content_type
        headers.update(resp.headers)
        return status, headers, data

    def _error(self, e: BoundaryError) -> tuple:
        status = (e.details or {}).get("http_status") or STATUS[e.code]
        details = {k: v for k, v in (e.details or {}).items() if k != "http_status"}
        rec = BoundaryError(e.code, e.message, details or None).to_record(PIPELINE_SCHEMA_VERSION)
        st, headers, data = self._json(status, rec)
        if status == 401:
            headers["WWW-Authenticate"] = "Bearer"
        return st, headers, data


class _HttpOnly(Exception):
    """BoundaryError 코드로 표현하지 않는 HTTP 층 응답(405, 413; CONVENTIONS 9절 보충 규칙)."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


def _query(environ) -> dict:
    from urllib.parse import parse_qs
    return {k: v[-1] for k, v in parse_qs(environ.get("QUERY_STRING", "")).items()}


def _headers(environ) -> dict:
    return {k[5:].replace("_", "-").lower(): v for k, v in environ.items() if k.startswith("HTTP_") and k != "HTTP_AUTHORIZATION"}
