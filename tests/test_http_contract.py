"""Exercise the final HTTP boundary against canonical service declarations."""
import io
import json

import pytest

from openit_link import App, Response, Route


def app(response=None, roles=("reader",)):
    return App([Route("GET", "/v1/question-sets", lambda _: response or Response(200, {"items": [], "next_cursor": None}),
                      roles=frozenset(roles), max_body=8 * 2**20)],
               {"token": "reader"}, contract_service="question-authoring",
               contract_bindings={"read_roles": list(roles), "write_roles": []})


def request(application, *, path="/v1/question-sets", query="", body=b"", token="token"):
    env = {"REQUEST_METHOD": "GET", "PATH_INFO": path, "QUERY_STRING": query,
           "CONTENT_LENGTH": str(len(body)), "wsgi.input": io.BytesIO(body)}
    if token:
        env["HTTP_AUTHORIZATION"] = "Bearer " + token
    status, headers, data = application.handle(env)
    return status, headers, json.loads(data)


def test_empty_allowed_roles_does_not_make_authenticated_operation_public():
    application = app(roles=())
    assert request(application, token=None)[0] == 401
    assert request(application)[0] == 403


@pytest.mark.parametrize("response", [Response(201, {"items": [], "next_cursor": None}),
    Response(200, {"items": [{}], "next_cursor": None}),
    Response(200, "wrong scalar", content_type="application/json"),
    Response(200, {"items": [], "next_cursor": None}, content_type="text/plain"),
    Response(401, {"pipeline_schema_version": "3.4", "code": "PERMISSION_DENIED", "message": "denied", "retryable": False})])
def test_invalid_status_payload_media_or_required_header_never_leaves_producer(response):
    status, _, body = request(app(response))
    assert (status, body["code"]) == (503, "UNAVAILABLE")


@pytest.mark.parametrize("query,body", [("limit=1&limit=2", b""), ("limit=", b""), ("unknown=1", b""), ("", b"{}")])
def test_request_rejects_ambiguous_unknown_or_forbidden_input(query, body):
    assert request(app(), query=query, body=body)[0] == 400


@pytest.mark.parametrize("path", ["/healthz", "/readyz"])
def test_health_requests_also_follow_declared_query_and_body_contract(path):
    assert request(app(), path=path)[0] == 200
    assert request(app(), path=path, query="extra=1")[0] == 400
    assert request(app(), path=path, body=b"{}")[0] == 400


def test_correct_route_and_result_pass():
    assert request(app())[0] == 200
    with pytest.raises(ValueError):
        App([Route("GET", "/v1/question-sets", lambda _: Response(200), roles=frozenset({"wrong"}), max_body=8 * 2**20)],
            {}, contract_service="question-authoring", contract_bindings={"read_roles": ["reader"], "write_roles": []})
