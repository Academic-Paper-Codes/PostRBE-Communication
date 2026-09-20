"""Versioned deterministic JSON serialization for evaluator-facing objects."""
from __future__ import annotations

import base64
import json
from typing import Any

import numpy as np

from .types import Ciphertext, OpeningProof, SecretKey, SerializationError, UserParams

FORMAT = "postrbe-json-v1"


def _matrix_to_json(matrix: np.ndarray) -> dict[str, Any]:
    array = np.asarray(matrix, dtype="<i8", order="C")
    return {
        "shape": list(array.shape),
        "dtype": "int64-le",
        "data_b64": base64.b64encode(array.tobytes(order="C")).decode("ascii"),
    }


def _matrix_from_json(value: Any) -> np.ndarray:
    try:
        if value["dtype"] != "int64-le":
            raise SerializationError("unsupported matrix dtype")
        shape = tuple(int(x) for x in value["shape"])
        raw = base64.b64decode(value["data_b64"], validate=True)
        array = np.frombuffer(raw, dtype="<i8")
        if array.size != int(np.prod(shape, dtype=object)):
            raise SerializationError("matrix byte count does not match shape")
        return array.reshape(shape).astype(np.int64, copy=True)
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, SerializationError):
            raise
        raise SerializationError("malformed matrix encoding") from exc


def _upload_to_json(upload: Any) -> Any:
    if upload is None:
        return None
    if isinstance(upload, (list, tuple)):
        return [None if item is None else _matrix_to_json(item) for item in upload]
    return _matrix_to_json(upload)


def _upload_from_json(upload: Any) -> Any:
    if upload is None:
        return None
    if isinstance(upload, list):
        return [None if item is None else _matrix_from_json(item) for item in upload]
    return _matrix_from_json(upload)


def _dumps(payload: dict[str, Any]) -> bytes:
    envelope = {"format": FORMAT, **payload}
    return json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _loads(data: bytes) -> dict[str, Any]:
    try:
        value = json.loads(data.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SerializationError("invalid serialized JSON") from exc
    if not isinstance(value, dict) or value.get("format") != FORMAT:
        raise SerializationError("unsupported or missing serialization format")
    return value


def serialize_secret_key(value: SecretKey) -> bytes:
    return _dumps({
        "type": "secret_key",
        "scheme": value.scheme,
        "instance_id": value.instance_id,
        "identity": value.identity,
        "block": value.block,
        "position": value.position,
        "X": _matrix_to_json(value.X),
    })


def deserialize_secret_key(data: bytes) -> SecretKey:
    value = _loads(data)
    if value.get("type") != "secret_key":
        raise SerializationError("object is not a secret key")
    return SecretKey(value["scheme"], value["instance_id"], int(value["identity"]), int(value["block"]), int(value["position"]), _matrix_from_json(value["X"]))


def serialize_user_params(value: UserParams) -> bytes:
    return _dumps({
        "type": "user_params",
        "scheme": value.scheme,
        "instance_id": value.instance_id,
        "identity": value.identity,
        "pk": _matrix_to_json(value.pk),
        "up": _upload_to_json(value.up),
    })


def deserialize_user_params(data: bytes) -> UserParams:
    value = _loads(data)
    if value.get("type") != "user_params":
        raise SerializationError("object is not user parameters")
    return UserParams(value["scheme"], value["instance_id"], int(value["identity"]), _matrix_from_json(value["pk"]), _upload_from_json(value["up"]))


def serialize_opening_proof(value: OpeningProof) -> bytes:
    return _dumps({
        "type": "opening_proof",
        "scheme": value.scheme,
        "instance_id": value.instance_id,
        "identity": value.identity,
        "block": value.block,
        "position": value.position,
        "state_version": value.state_version,
        "opening": _matrix_to_json(value.opening),
    })


def deserialize_opening_proof(data: bytes) -> OpeningProof:
    value = _loads(data)
    if value.get("type") != "opening_proof":
        raise SerializationError("object is not an opening proof")
    return OpeningProof(value["scheme"], value["instance_id"], int(value["identity"]), int(value["block"]), int(value["position"]), int(value["state_version"]), _matrix_from_json(value["opening"]))


def serialize_ciphertext(value: Ciphertext) -> bytes:
    """Serialize a ciphertext without the local-only correctness audit value."""
    return _dumps({
        "type": "ciphertext",
        "scheme": value.scheme,
        "instance_id": value.instance_id,
        "identity": value.identity,
        "block": value.block,
        "position": value.position,
        "state_version": value.state_version,
        "c1": _matrix_to_json(value.c1),
        "c2": _matrix_to_json(value.c2),
        "reconciliation_hint": _matrix_to_json(value.reconciliation_hint),
        "nonce_b64": base64.b64encode(value.nonce).decode("ascii"),
        "c3_b64": base64.b64encode(value.c3).decode("ascii"),
    })


def deserialize_ciphertext(data: bytes) -> Ciphertext:
    value = _loads(data)
    if value.get("type") != "ciphertext":
        raise SerializationError("object is not a ciphertext")
    try:
        nonce = base64.b64decode(value["nonce_b64"], validate=True)
        c3 = base64.b64decode(value["c3_b64"], validate=True)
    except (KeyError, ValueError) as exc:
        raise SerializationError("malformed ciphertext byte encoding") from exc
    return Ciphertext(
        value["scheme"],
        value["instance_id"],
        int(value["identity"]),
        int(value["block"]),
        int(value["position"]),
        int(value["state_version"]),
        _matrix_from_json(value["c1"]),
        _matrix_from_json(value["c2"]),
        _matrix_from_json(value["reconciliation_hint"]),
        nonce,
        c3,
    )


def serialized_size(value: SecretKey | UserParams | OpeningProof | Ciphertext) -> int:
    if isinstance(value, SecretKey):
        return len(serialize_secret_key(value))
    if isinstance(value, UserParams):
        return len(serialize_user_params(value))
    if isinstance(value, OpeningProof):
        return len(serialize_opening_proof(value))
    if isinstance(value, Ciphertext):
        return len(serialize_ciphertext(value))
    raise TypeError(f"unsupported serialized object: {type(value).__name__}")
