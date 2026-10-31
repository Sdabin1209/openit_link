"""영역 통신의 받는 쪽 기반(D118): 계약 HTTP 규약(CONVENTIONS 6·9절)을 한 곳에서 지키는 WSGI 앱.

영역의 받는 쪽 통신 컴포넌트(`link_*`)는 경로마다 Route(메서드, 경로 패턴, 요청 스키마, 응답 스키마, 허용 역할, 사람 머리글 필요 여부, 처리 함수)만 적는다.
이 모듈이 하는 일: 토큰 → 역할(없거나 틀리면 401 + WWW-Authenticate, 역할이 맞지 않으면 403), `X-Openit-User`(필요한 경로에서 없으면 401),
본문 상한(413), JSON 해석, 요청을 계약 스키마로 검증(400 INVALID_RECORD), 처리 함수가 낸 값을 응답 스키마로 검증(내는 쪽 검증, R7),
`BoundaryError` → 상태 코드(CONVENTIONS 9절 표), `/healthz`·`/readyz`.
왜 WSGI: 영역 서버가 모두 waitress(WSGI) 위에서 돈다(2026-10-30 확인). 프레임워크를 새로 들이지 않고 표준 인터페이스(PEP 3333)만 쓴다.
"""
from __future__ import annotations

import hmac
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional

from boundary_contracts import PIPELINE_SCHEMA_VERSION, BoundaryError, load_schema, validator
import jsonschema

# CONVENTIONS 9절의 고정 표. 401은 PERMISSION_DENIED + details.http_status 401로 낸다(D106).
STATUS = {"INVALID_RECORD": 400, "PERMISSION_DENIED": 403, "NOT_FOUND": 404, "CONFLICT": 409,
          "FAILED_PRECONDITION": 412, "UNSUPPORTED_VERSION": 422, "INTEGRITY_ERROR": 422, "UNAVAILABLE": 503}
REASON = {200: "OK", 201: "Created", 202: "Accepted", 204: "No Content", 400: "Bad Request", 401: "Unauthorized",
          403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed", 409: "Conflict", 412: "Precondition Failed",
          413: "Content Too Large", 422: "Unprocessable Content", 503: "Service Unavailable"}
_log = logging.getLogger("openit_link")
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
    actor: Optional[str] = None            # 0.2.0: 토큰에 묶인 호출자 ID(토큰 표의 값이 {"role", "actor"}일 때)
    stream: Any = None                     # 0.3.0: Route.stream_body일 때 본문 읽기 객체(read(n), Content-Length 상한)
    content_length: Optional[int] = None   # 0.4.1: 요청의 Content-Length(없으면 None). 스트리밍 본문의 크기를 미리 판단할 때 쓴다


@dataclass(frozen=True)
class Response:
    status: int
    body: Any = None                       # dict·list면 JSON, str이면 text/plain, bytes면 그대로, bytes를 내는 반복자면 나눠 보낸다(0.2.0, 큰 파일)
    headers: Mapping[str, str] = field(default_factory=dict)
    content_type: Optional[str] = None


@dataclass(frozen=True)
class Route:
    method: str
    pattern: str                           # 예: "/v1/cases/{case_id}/review"
    handler: Callable[[Request], Response]
    roles: frozenset = frozenset()         # 빈 집합이면 인증 없음(공개 경로)
    request_schema: Optional[str] = None   # 계약 스키마 이름. JSON 본문을 이것으로 검증한다. "이름#/$defs/X"로 하위 정의를 가리킬 수 있다(0.2.0)
    query_schema: Optional[str] = None     # 0.2.0: 쿼리 문자열(문자열 값 dict)을 검증할 스키마(계약 이름 또는 "이름#/$defs/X")
    response_schema: Optional[str] = None  # 2xx JSON 본문을 이것으로 검증한다(내는 쪽 검증)
    require_user: bool = False             # 사람 행위자(X-Openit-User)가 필요한 쓰기
    raw_body: bool = False                 # JSON이 아닌 본문(tar 등)을 그대로 넘긴다
    stream_body: bool = False              # 0.3.0: 본문을 메모리에 올리지 않고 Request.stream(상한 걸린 읽기 객체)으로 넘긴다(수 GiB 게시)
    max_body: int = DEFAULT_MAX_BODY

    def compiled(self):
        rx = "^" + re.sub(r"\\\{(\w+)\\\}", r"(?P<\1>[^/]+)", re.escape(self.pattern)) + "$"
        return re.compile(rx)


class HttpError(Exception):
    """0.3.0: BoundaryError에 응답 머리글(예: Retry-After)을 붙여 낸다. 처리 함수가 `raise HttpError(BoundaryError(...), {"Retry-After": "2"})`."""

    def __init__(self, error: BoundaryError, headers: Optional[Mapping[str, str]] = None):
        super().__init__(error.message)
        self.error, self.headers = error, dict(headers or {})


def _unauth(message: str) -> BoundaryError:
    return BoundaryError("PERMISSION_DENIED", message, {"http_status": 401})


class App:
    """WSGI 앱. tokens: 토큰 문자열 → 역할 이름(비밀은 파일에서 읽어 넘긴다, D84). ready: /readyz 판정 함수 → (준비됨, 본문 dict)."""

    def __init__(self, routes: list[Route], tokens: Mapping[str, str], *, ready: Optional[Callable[[], tuple]] = None,
                 user_header_trusted: bool = True, authenticate: Optional[Callable[[Mapping[str, str]], Optional[tuple]]] = None,
                 ready_public: Optional[Callable[[dict], dict]] = None, max_json_depth: int = 64,
                 on_result: Optional[Callable[[dict], None]] = None):
        """authenticate(0.3.0): 토큰이 없을 때 부르는 추가 인증(예: 게이트웨이가 확인한 X-Openit-Device를 믿는 내부망 경로, ADR 0012).
        요청 머리글(소문자 이름) → (역할, 호출자 ID) 또는 None. ready_public(0.3.0): 인증되지 않은 /readyz 호출에 줄 본문(사유를 감춘다);
        인증된 호출(토큰 표의 토큰)에는 ready()의 본문 전체를 준다. max_json_depth(0.3.0): JSON 중첩 상한(넘으면 400, 재귀 한도로 죽지 않게)."""
        self._routes = [(r, r.compiled()) for r in routes]
        # 토큰 표: 토큰 → 역할 문자열, 또는 {"role": 역할, "actor": 호출자 ID}(0.2.0). 비교는 상수 시간(hmac.compare_digest)으로 모든 후보를 끝까지 본다
        self._tokens = [(t.encode(), (v["role"], v.get("actor")) if isinstance(v, Mapping) else (v, None)) for t, v in tokens.items()]
        self._ready = ready
        self._user_trusted = user_header_trusted   # 게이트웨이 뒤 내부망에서만 X-Openit-User를 믿는다(게이트웨이가 덮어쓴다, D88)
        self._authenticate = authenticate
        self._ready_public = ready_public
        self._max_depth = max_json_depth
        # on_result(0.4.0): 경로가 있는 요청이 끝날 때마다(성공·거부·실패 모두) {"method","pattern","status","code","role","actor","user","params"}로 부른다.
        # 감사 기록용(누가 무엇을 시도했다가 왜 거부됐나). 훅의 예외는 응답을 바꾸지 않는다(기록 실패가 요청 실패가 되지 않게)
        self._on_result = on_result

    # ---- WSGI ----
    def __call__(self, environ, start_response):
        status, headers, body = self.handle(environ)
        start_response(f"{status} {REASON.get(status, '')}".strip(), list(headers.items()))
        return [body] if isinstance(body, (bytes, bytearray)) else body   # 반복자는 WSGI 서버가 나눠 보낸다(PEP 3333)

    def handle(self, environ) -> tuple:
        ctx: dict = {}   # 요청마다 따로(waitress는 여러 스레드에서 동시에 부른다)
        out = self._handle(environ, ctx)
        if self._on_result is not None and ctx:
            try:
                code = None
                if out[0] >= 400 and isinstance(out[2], (bytes, bytearray)):
                    try:
                        code = json.loads(out[2]).get("code")
                    except ValueError:
                        code = None
                self._on_result({**ctx, "status": out[0], "code": code})
            except Exception:   # noqa: BLE001 — 기록 실패가 응답을 바꾸지 않는다
                pass
        return out

    def _handle(self, environ, ctx: dict) -> tuple:
        method = environ.get("REQUEST_METHOD", "GET").upper()
        path = environ.get("PATH_INFO", "/")
        raw_path = (environ.get("REQUEST_URI") or environ.get("RAW_URI") or "").split("?", 1)[0]   # 0.2.0: %2F를 보존한 원래 경로(waitress·gunicorn이 준다)
        try:
            if path == "/healthz" and method == "GET":
                return self._json(200, {"status": "ok"})
            if path == "/readyz" and method == "GET":
                ok, info = self._ready() if self._ready else (True, {"status": "ready"})
                if self._ready_public is not None and self._principal(environ) is None:
                    info = self._ready_public(info)
                return self._json(200 if ok else 503, info)
            route, params = self._match(method, raw_path or path, encoded=bool(raw_path))
            principal = self._principal(environ)
            ctx.update({"method": method, "pattern": route.pattern, "params": dict(params),
                         "role": principal[0] if principal else None, "actor": principal[1] if principal else None,
                         "user": environ.get("HTTP_X_OPENIT_USER") if self._user_trusted else None})
            if route.stream_body:
                stream = self._stream(environ, route.max_body)
                raw = b""
            else:
                stream = None
                raw = self._read(environ, route.max_body)   # 전송 한도(413)는 앱 판단보다 먼저다(CONVENTIONS 9절 2.2.2: HTTP 서버가 앱을 부르기 전에 낸다)
            role, actor = self._auth(route, environ)
            user = environ.get("HTTP_X_OPENIT_USER") if self._user_trusted else None
            if route.require_user and not user:
                raise _unauth("사람 행위자(X-Openit-User)가 없다")
            body = None
            if raw and not route.raw_body:
                body = _strict_json(raw, self._max_depth)
            query = _query(environ)
            if route.request_schema is not None:
                _validate(route.request_schema, body)
            if route.query_schema is not None:
                _validate(route.query_schema, query)
            req = Request(method, path, params, query, body, raw, role, user, _headers(environ), actor, stream, _content_length(environ))
            resp = route.handler(req)
            if route.response_schema is not None and 200 <= resp.status < 300 and isinstance(resp.body, (dict, list)):
                errs = _errors(route.response_schema, resp.body)
                if errs:   # 내는 쪽이 계약을 어기면 받는 쪽에 틀린 값을 보내지 않는다: 서버 결함
                    raise BoundaryError("UNAVAILABLE", f"응답이 {route.response_schema}를 어긴다(서버 결함)")
            return self._out(resp)
        except BoundaryError as e:
            return self._error(e)
        except HttpError as e:
            st, headers, data = self._error(e.error)
            headers.update(e.headers)
            return st, headers, data
        except _HttpOnly as e:   # 0.4.0: 405·413도 본문은 BoundaryError(CONVENTIONS 9절 "실패는 BoundaryError 레코드"). 코드는 INVALID_RECORD, 원래 상태는 http_status
            st, headers, data = self._error(BoundaryError("INVALID_RECORD", e.message, {"http_status": e.status}))
            headers.update(e.headers)
            return st, headers, data
        except Exception:   # noqa: BLE001 — 0.4.2: 처리 함수의 예기치 않은 예외도 BoundaryError 레코드로 낸다(CONVENTIONS 9절 "실패는 BoundaryError 레코드"). 서버 결함이라 503 UNAVAILABLE, 예외 내용은 응답에 싣지 않고 로그에만(값·비밀이 새지 않게)
            _log.exception("처리 중 예기치 않은 예외 (%s %s)", method, ctx.get("pattern", path))
            return self._error(BoundaryError("UNAVAILABLE", "서버 내부 오류"))

    # ---- 내부 ----
    def _match(self, method: str, path: str, encoded: bool = False):
        from urllib.parse import unquote
        allowed = []
        for r, rx in self._routes:
            m = rx.match(path)
            if m:
                if r.method == method:   # 경로 조각은 나눈 뒤에 하나씩 푼다: 조각 안의 %2F가 경로 구분자로 바뀌지 않는다
                    return r, ({k: unquote(v) for k, v in m.groupdict().items()} if encoded else m.groupdict())
                allowed.append(r.method)
        if allowed:
            raise _HttpOnly(405, "허용하지 않는 메서드", {"Allow": ", ".join(sorted(set(allowed)))})
        raise BoundaryError("NOT_FOUND", "경로가 없다")

    def _auth(self, route: Route, environ) -> tuple:
        if not route.roles:
            return None, None
        found = self._principal(environ)
        if found is None and self._authenticate is not None and not environ.get("HTTP_AUTHORIZATION"):
            found = self._authenticate(_headers(environ))
        if found is None:
            raise _unauth("토큰이 없거나 틀리다")
        role, actor = found
        if role not in route.roles:
            raise BoundaryError("PERMISSION_DENIED", "이 호출을 할 권한이 없다")
        return role, actor

    def _principal(self, environ) -> Optional[tuple]:
        auth = environ.get("HTTP_AUTHORIZATION", "")
        given = auth[7:].encode() if auth.startswith("Bearer ") else b""
        found = None
        for tok, principal in self._tokens:   # 일치해도 멈추지 않는다: 어느 후보와 맞았는지가 시간에 드러나지 않게(타이밍 공격 방어)
            if hmac.compare_digest(given, tok) and given:
                found = principal
        return found

    @staticmethod
    def _stream(environ, limit: int):
        try:
            n = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            raise BoundaryError("INVALID_RECORD", "Content-Length가 잘못됐다") from None
        if n < 0:   # 0.4.2: 음수면 상한 검사를 지나쳐 read(-n)이 본문 전체를 한도 없이 읽는다(RFC 9110 8.6: 0 이상의 정수)
            raise BoundaryError("INVALID_RECORD", "Content-Length가 잘못됐다")
        if n > limit:
            raise _HttpOnly(413, f"본문이 상한({limit}바이트)을 넘는다")
        return _Limited(environ["wsgi.input"], n)

    @staticmethod
    def _read(environ, limit: int) -> bytes:
        try:
            n = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            raise BoundaryError("INVALID_RECORD", "Content-Length가 잘못됐다") from None
        if n < 0:   # 0.4.2: 음수면 상한 검사를 지나쳐 read(-n)이 본문 전체를 한도 없이 읽는다(RFC 9110 8.6: 0 이상의 정수)
            raise BoundaryError("INVALID_RECORD", "Content-Length가 잘못됐다")
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
        else:   # bytes 또는 bytes 반복자(스트리밍)
            status, headers, data = resp.status, {"Content-Type": resp.content_type or "application/octet-stream"}, b if b is not None else b""
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

    def __init__(self, status: int, message: str, headers: Optional[dict] = None):
        super().__init__(message)
        self.status, self.message, self.headers = status, message, headers or {}


class _Limited:
    """Content-Length만큼만 읽게 하는 본문 읽기 객체(0.3.0). 상한을 넘겨 읽지 않는다."""

    def __init__(self, f, n: int):
        self._f, self.remaining = f, n

    def read(self, size: int = -1) -> bytes:
        if self.remaining <= 0:
            return b""
        size = self.remaining if size is None or size < 0 else min(size, self.remaining)
        data = self._f.read(size)
        self.remaining -= len(data)
        return data


def _no_dup(pairs):
    seen = {}
    for k, v in pairs:
        if k in seen:
            raise ValueError(f"중복 키 {k!r}")
        seen[k] = v
    return seen


def _depth(o, limit: int, d: int = 0) -> None:
    if d > limit:
        raise ValueError("중첩이 너무 깊다")
    if isinstance(o, dict):
        for v in o.values():
            _depth(v, limit, d + 1)
    elif isinstance(o, list):
        for v in o:
            _depth(v, limit, d + 1)


def _strict_json(raw: bytes, max_depth: int):
    """0.3.0: I-JSON(RFC 7493)에 맞춰 받는다 — UTF-8, 중복 키 거부, 짝 없는 서로게이트 거부, 중첩 상한. 어기면 400 INVALID_RECORD."""
    try:
        text = raw.decode("utf-8")
        if raw.count(b"[") + raw.count(b"{") > max_depth and _bracket_depth(text) > max_depth:
            raise ValueError("중첩이 너무 깊다")
        obj = json.loads(text, object_pairs_hook=_no_dup)
        json.dumps(obj, ensure_ascii=False).encode("utf-8")   # 짝 없는 서로게이트는 여기서 UnicodeEncodeError
        _depth(obj, max_depth)
        return obj
    except (ValueError, UnicodeError, RecursionError) as e:
        raise BoundaryError("INVALID_RECORD", f"본문이 올바른 JSON이 아니다: {str(e)[:120]}") from None


def _bracket_depth(text: str) -> int:
    """문자열 밖의 괄호 깊이(재귀 없이). json.loads가 깊은 중첩에서 RecursionError로 죽기 전에 거른다."""
    d = m = 0
    in_str = esc = False
    for ch in text:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in "[{":
            d += 1
            m = max(m, d)
        elif ch in "]}":
            d -= 1
    return m


def _resolve(ref: str):
    """"이름" 또는 "이름#/$defs/X" → 검증기. 하위 정의는 상위 스키마의 $defs·$ref를 그대로 쓴다."""
    name, _, frag = ref.partition("#")
    if not frag:
        return validator(name)
    top = load_schema(name)
    sub = dict(top)
    for k in [x for x in frag.split("/") if x]:
        sub = sub[k]
    wrapped = {**{k: v for k, v in top.items() if k in ("$schema", "$id", "$defs")}, "$ref": "#" + frag}
    base = validator(name)
    return type(base)(wrapped, resolver=getattr(base, "resolver", None)) if getattr(base, "resolver", None) else type(base)(wrapped)


def _errors(ref: str, value) -> list:
    return [e.message for e in _resolve(ref).iter_errors(value)]


def _validate(ref: str, value) -> None:
    errs = _errors(ref, value)
    if errs:
        raise BoundaryError("INVALID_RECORD", f"{ref} 위반: {errs[0][:200]}")


def _query(environ) -> dict:
    from urllib.parse import parse_qs
    return {k: v[-1] for k, v in parse_qs(environ.get("QUERY_STRING", "")).items()}


def _headers(environ) -> dict:
    """요청 머리글(소문자). WSGI는 Content-Length·Content-Type을 HTTP_ 접두사 없이 주므로 함께 담는다(0.4.1, PEP 3333). Authorization은 넣지 않는다(비밀)."""
    h = {k[5:].replace("_", "-").lower(): v for k, v in environ.items() if k.startswith("HTTP_") and k != "HTTP_AUTHORIZATION"}
    for k, name in (("CONTENT_LENGTH", "content-length"), ("CONTENT_TYPE", "content-type")):
        if environ.get(k):
            h[name] = environ[k]
    return h


def _content_length(environ) -> Optional[int]:
    try:
        n = int(environ["CONTENT_LENGTH"]) if environ.get("CONTENT_LENGTH") else None
        return n if n is None or n >= 0 else None
    except ValueError:
        return None