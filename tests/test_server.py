"""받는 쪽 기반이 계약 HTTP 규약(CONVENTIONS 6·9절)을 지키는지: 실제 waitress 위에서 계약 클라이언트로 부른다."""
import json
import threading
import unittest
import urllib.error
import urllib.request

import waitress
from boundary_contracts import validator

from openit_link import App, Response, Route

TOK = {"op-token-0123456789": "operator", "read-token-0123456789": "reader"}


def activate(req):
    return Response(200, {"pipeline_schema_version": "3.1", "release_id": req.body["release_id"], "activated_at": "2026-10-30T00:00:00Z",
                          "activated_by_role": "operator"})


class Server(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        routes = [Route("POST", "/v1/activate", activate, roles=frozenset({"operator"}), request_schema="ActivateRequest", require_user=True),
                  Route("GET", "/v1/things/{tid}", lambda r: Response(200, {"id": r.params["tid"]}), roles=frozenset({"operator", "reader"})),
                  Route("GET", "/v1/bad", lambda r: Response(200, {"not": "a pointer"}), roles=frozenset({"operator"}), response_schema="ActivePointer")]
        cls.app = App(routes, TOK, ready=lambda: (False, {"status": "not-ready", "db": "down"}))
        cls.srv = waitress.create_server(cls.app, host="127.0.0.1", port=0)
        cls.port = cls.srv.effective_port
        threading.Thread(target=cls.srv.run, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.close()

    def call(self, method, path, body=None, token=None, user=None):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", method=method,
                                     data=json.dumps(body).encode() if body is not None else None)
        if token:
            req.add_header("Authorization", "Bearer " + token)
        if user:
            req.add_header("X-Openit-User", user)
        if body is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, r.headers, json.loads(r.read() or b"null")
        except urllib.error.HTTPError as e:
            return e.code, e.headers, json.loads(e.read() or b"null")

    def test_토큰_없음_틀림은_401과_WWW_Authenticate(self):
        for tok in (None, "wrong"):
            c, h, b = self.call("GET", "/v1/things/a", token=tok)
            self.assertEqual((c, h.get("WWW-Authenticate"), b["code"]), (401, "Bearer", "PERMISSION_DENIED"))
            self.assertEqual(list(validator("BoundaryError").iter_errors(b)), [])

    def test_역할이_맞지_않으면_403(self):
        c, _, b = self.call("POST", "/v1/activate", {"release_id": "r1", "requested_by_role": "operator"}, token="read-token-0123456789", user="u")
        self.assertEqual((c, b["code"]), (403, "PERMISSION_DENIED"))

    def test_사람_머리글이_없으면_401(self):
        c, _, _ = self.call("POST", "/v1/activate", {"release_id": "r1", "requested_by_role": "operator"}, token="op-token-0123456789")
        self.assertEqual(c, 401)

    def test_요청은_계약_스키마로_검증(self):
        c, _, b = self.call("POST", "/v1/activate", {"release_id": "r1", "requested_by_role": "model-lab"}, token="op-token-0123456789", user="u")
        self.assertEqual((c, b["code"]), (400, "INVALID_RECORD"))
        c, _, b = self.call("POST", "/v1/activate", {"release_id": "r1", "requested_by_role": "operator"}, token="op-token-0123456789", user="u")
        self.assertEqual((c, b["release_id"]), (200, "r1"))

    def test_응답이_계약을_어기면_내보내지_않는다(self):
        c, _, b = self.call("GET", "/v1/bad", token="op-token-0123456789")
        self.assertEqual((c, b["code"]), (503, "UNAVAILABLE"))

    def test_없는_경로_404_경로_변수(self):
        self.assertEqual(self.call("GET", "/v1/nothing", token="op-token-0123456789")[0], 404)
        self.assertEqual(self.call("GET", "/v1/things/x-1", token="read-token-0123456789")[2], {"id": "x-1"})

    def test_healthz_readyz(self):
        self.assertEqual(self.call("GET", "/healthz")[0], 200)
        c, _, b = self.call("GET", "/readyz")
        self.assertEqual((c, b["db"]), (503, "down"))

    def test_본문_상한_413(self):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/v1/activate", method="POST", data=b"x" * (2 * 2**20))
        req.add_header("Authorization", "Bearer op-token-0123456789")
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req, timeout=10)
        self.assertEqual(cm.exception.code, 413)


class Clients(unittest.TestCase):
    def test_계약_클라이언트를_다시_내보낸다(self):
        from openit_link import clients
        from boundary_contracts.clients import HttpGateService
        self.assertIs(clients.HttpGateService, HttpGateService)


if __name__ == "__main__":
    unittest.main()


class V020(unittest.TestCase):
    """0.2.0: $defs 참조, 쿼리 검증, 호출자 ID, 상수 시간 비교, 스트리밍, %2F 보존, 405 Allow."""
    @classmethod
    def setUpClass(cls):
        def stream(req):
            return Response(200, (b"x" * 1024 for _ in range(4)), content_type="application/octet-stream")
        routes = [Route("POST", "/v1/purge", lambda r: Response(200, r.body), roles=frozenset({"operator"}),
                        request_schema="QuestionAuthoringDeployInterface#/$defs/PurgeResult"),
                  Route("GET", "/v1/files/{path}", lambda r: Response(200, {"path": r.params["path"], "actor": r.actor}), roles=frozenset({"operator"})),
                  Route("GET", "/v1/stream", stream, roles=frozenset({"operator"}))]
        cls.app = App(routes, {"op-token-0123456789": {"role": "operator", "actor": "svc-a"}})
        cls.srv = waitress.create_server(cls.app, host="127.0.0.1", port=0)
        cls.port = cls.srv.effective_port
        threading.Thread(target=cls.srv.run, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.close()

    def raw(self, method, path, data=None):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", method=method, data=data)
        req.add_header("Authorization", "Bearer op-token-0123456789")
        if data:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, r.headers, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read()

    def test_defs_참조로_검증(self):
        self.assertEqual(self.raw("POST", "/v1/purge", json.dumps({"drafts_removed": 1, "sources_removed": 0}).encode())[0], 200)
        self.assertEqual(self.raw("POST", "/v1/purge", json.dumps({"drafts_removed": -1, "sources_removed": 0}).encode())[0], 400)

    def test_호출자_ID와_퍼센트_인코딩_보존(self):
        c, _, b = self.raw("GET", "/v1/files/a%2Fb.jsonl")
        self.assertEqual((c, json.loads(b)), (200, {"path": "a/b.jsonl", "actor": "svc-a"}))

    def test_스트리밍(self):
        c, _, b = self.raw("GET", "/v1/stream")
        self.assertEqual((c, len(b)), (200, 4096))

    def test_405에_Allow(self):
        c, h, _ = self.raw("DELETE", "/v1/stream")
        self.assertEqual((c, h.get("Allow")), (405, "GET"))
