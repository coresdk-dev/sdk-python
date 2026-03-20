"""Test RFC 9457 ProblemDetailError."""
import json

from coresdk.errors._rfc9457 import ProblemDetailError


def test_to_dict():
    err = ProblemDetailError("Not Found", 404, detail="Resource missing",
                              type_uri="https://example.com/not-found")
    d = err.to_dict()
    assert d["status"] == 404
    assert d["title"] == "Not Found"
    assert d["detail"] == "Resource missing"
    assert d["type"] == "https://example.com/not-found"


def test_to_json_roundtrip():
    err = ProblemDetailError("Bad Request", 400, detail="Invalid input")
    j = err.to_json()
    parsed = json.loads(j)
    assert parsed["status"] == 400


def test_factory_unauthorized():
    err = ProblemDetailError.unauthorized("Bad token")
    assert err.status == 401
    assert err.title == "Unauthorized"


def test_factory_forbidden():
    err = ProblemDetailError.forbidden("Access denied")
    assert err.status == 403


def test_is_exception():
    err = ProblemDetailError("Error", 500)
    assert isinstance(err, Exception)
