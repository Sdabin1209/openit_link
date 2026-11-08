"""계약 JSON 공통 규칙(boundary-contracts 5.0.0 CONVENTIONS 10절, I-JSON RFC 7493)을 받는 입구와 내는 출구가 지키는지.
왜 이 시험이 있나: 규칙의 구현은 계약 strict_json 이 정본이고 link 는 그것을 부르는 배선만 맡는다. 배선이 빠지면(예: 옛 자체 해석으로 되돌림)
NaN·1e999 가 통과하므로 입구·출구에서 경계값을 직접 건다. 계약 구현 자체의 시험은 계약 리포 몫이다."""
import threading
import unittest
import urllib.error
import urllib.request

import waitress

from openit_link import App, Response, Route

TOK = {"op-token-0123456789": "operator"}


def nested(n: int) -> bytes:
    return b"[" * n + b"]" * n


class JsonRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        routes = [Route("POST", "/v1/echo", lambda r: Response(200, {"ok": True}), roles=frozenset({"operator"})),
                  Route("POST", "/v1/bin", lambda r: Response(200, {"n": len(r.raw)}), roles=frozenset({"operator"}), raw_body=True),
                  Route("GET", "/v1/nan", lambda r: Response(200, {"x": float("nan")}), roles=frozenset({"operator"})),
                  Route("GET", "/v1/inf", lambda r: Response(200, {"x": float("inf")}), roles=frozenset({"operator"})),
                  Route("GET", "/v1/bigint", lambda r: Response(200, {"x": 2**53 + 1}), roles=frozenset({"operator"})),
                  Route("GET", "/v1/deep", lambda r: Response(200, {"x": _deep(64)}), roles=frozenset({"operator"})),
                  Route("GET", "/v1/huge", lambda r: Response(200, {"x": "a" * (2**20)}), roles=frozenset({"operator"})),
                  Route("GET", "/v1/fine", lambda r: Response(200, {"x": 2**53, "y": 1.5}), roles=frozenset({"operator"}))]
        cls.srv = waitress.create_server(App(routes, TOK), host="127.0.0.1", port=0)
        cls.port = cls.srv.effective_port
        threading.Thread(target=cls.srv.run, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.task_dispatcher.shutdown(cancel_pending=True, timeout=5)
        cls.srv.close()

    def raw(self, method, path, data=None):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", method=method, data=data)
        req.add_header("Authorization", "Bearer op-token-0123456789")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code

    def post(self, data: bytes) -> int:
        return self.raw("POST", "/v1/echo", data)

    def test_입구_받는_값(self):
        for ok in (b'{"a": 1}', b'{"a": 9007199254740992}', b'{"a": -9007199254740992}', b'{"a": 1.5e300}', nested(64)):
            self.assertEqual(self.post(ok), 200, ok[:40])

    def test_입구_NaN_Infinity_오버플로_거부(self):
        for bad in (b'{"a": NaN}', b'{"a": Infinity}', b'{"a": -Infinity}', b'{"a": 1e999}', b'{"a": -1e999}'):
            self.assertEqual(self.post(bad), 400, bad)

    def test_입구_2의53제곱_밖_정수_거부(self):
        for bad in (b'{"a": 9007199254740993}', b'{"a": -9007199254740993}'):
            self.assertEqual(self.post(bad), 400, bad)

    def test_입구_깊이_64_통과_65_거부(self):
        self.assertEqual(self.post(nested(64)), 200)
        self.assertEqual(self.post(nested(65)), 400)
        self.assertEqual(self.post(nested(100000)), 400)   # 재귀 한도로 500 이 나지 않는다

    def test_입구_값_개수_상한(self):
        # 값 하나 최소 2바이트("0,")라 1 MiB 안에서는 2**19 를 넘지 못한다. 상한 안에서 최대로 채운 본문은 받는다
        body = b"[" + b"0," * (2**19 - 2) + b"0]"
        self.assertLessEqual(len(body), 2**20)
        self.assertEqual(self.post(body), 200)
        over = b"[" + b"0," * (2**19) + b"0]"   # 값 2**19 + 1 개(바이트도 1 MiB 를 넘어 413)
        self.assertEqual(self.post(over), 413)

    def test_입구_중복_키_서로게이트_거부(self):
        self.assertEqual(self.post(b'{"a": 1, "a": 2}'), 400)
        self.assertEqual(self.post(b'{"a": "\\ud800"}'), 400)
        self.assertEqual(self.post(b'{"a": "\xff"}'), 400)   # UTF-8 이 아니다

    def test_입구_본문_상한은_413(self):
        self.assertEqual(self.post(b'["' + b"a" * (2**20) + b'"]'), 413)

    def test_바이너리_경로는_JSON_규칙을_받지_않는다(self):
        self.assertEqual(self.raw("POST", "/v1/bin", b"\xff\x00NaN"), 200)

    def test_출구_NaN_무한대_범위밖_정수_깊이_상한은_503(self):
        for path in ("/v1/nan", "/v1/inf", "/v1/bigint", "/v1/deep", "/v1/huge"):
            self.assertEqual(self.raw("GET", path), 503, path)

    def test_출구_경계값은_내보낸다(self):
        self.assertEqual(self.raw("GET", "/v1/fine"), 200)


def _deep(n: int):
    v: list = []
    for _ in range(n - 1):
        v = [v]
    return v


if __name__ == "__main__":
    unittest.main()
