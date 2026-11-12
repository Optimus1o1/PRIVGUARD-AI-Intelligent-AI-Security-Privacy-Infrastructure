"""Unit tests for payload serialization."""

from pydantic import BaseModel

from privguard_sdk.transport.serialization import serialize_payload, to_json_bytes


class SampleModel(BaseModel):
    name: str
    count: int
    optional_val: str = None


def test_serialize_payload():
    model = SampleModel(name="test", count=42)
    serialized = serialize_payload(model)
    assert serialized == {"name": "test", "count": 42}
    assert "optional_val" not in serialized

    dict_payload = {"key": "val", "none_key": None}
    assert serialize_payload(dict_payload) == {"key": "val"}


def test_to_json_bytes():
    payload = {"a": 1, "b": "hello"}
    b = to_json_bytes(payload)
    assert b == b'{"a":1,"b":"hello"}'
