"""Strict DarkVault profile over standard JOSE primitives."""

import base64
import json
import re
from typing import Any

from jwcrypto import jwe, jwk

MAX_BODY = 2 * 1024 * 1024
MAX_PLAINTEXT = 1536 * 1024
ALGORITHMS = ["ECDH-ES", "A256GCM"]


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("Duplicate JSON field")
        result[name] = value
    return result


def _constant(_: str) -> None:
    raise ValueError("Non-finite JSON number")


def loads(data: bytes) -> dict[str, Any]:
    if len(data) > MAX_PLAINTEXT:
        raise ValueError("Payload too large")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_object, parse_constant=_constant)
        if not isinstance(value, dict):
            raise ValueError("Expected JSON object")

        def check(node: Any, depth: int) -> None:
            if isinstance(node, (dict, list)):
                if depth > 16:
                    raise ValueError("JSON too deep")
                if isinstance(node, dict):
                    for key in node:
                        key.encode("utf-8")
                for item in node.values() if isinstance(node, dict) else node:
                    check(item, depth + 1)
            elif isinstance(node, str):
                node.encode("utf-8")

        check(value, 1)
        return value
    except (ValueError, RecursionError):
        raise ValueError("Invalid JSON payload") from None


def dumps(value: dict[str, Any]) -> bytes:
    try:
        result = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
        loads(result)
        return result
    except (ValueError, TypeError, RecursionError):
        raise ValueError("Invalid request payload") from None


def unbase64(value: str) -> bytes:
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9_-]*", value) is None:
        raise ValueError("Invalid base64url")
    data = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    if base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii") != value:
        raise ValueError("Noncanonical base64url")
    return data


def public_key(value: Any) -> jwk.JWK:
    if not isinstance(value, dict) or not {"kty", "crv", "x", "y"}.issubset(value) or {"d", "p", "q", "dp", "dq", "qi", "oth"}.intersection(value):
        raise ValueError("Invalid public key fields")
    if value["kty"] != "EC" or value["crv"] != "P-256":
        raise ValueError("Unsupported public key")
    if len(unbase64(value["x"])) != 32 or len(unbase64(value["y"])) != 32:
        raise ValueError("Invalid public key coordinates")
    key = jwk.JWK(**value)
    key.get_op_key("encrypt")  # Let the cryptography backend validate the curve point.
    return key


def encrypt(payload: dict[str, Any], recipient: jwk.JWK, kid: str, kind: str) -> bytes:
    header = {"alg": "ECDH-ES", "enc": "A256GCM", "kid": kid, "typ": kind, "cty": "application/json"}
    token = jwe.JWE(dumps(payload), protected=dumps(header).decode("utf-8"), algs=ALGORITHMS)
    token.add_recipient(recipient)
    serialized = token.serialize(compact=True)
    result: bytes = serialized.encode("ascii")
    if len(result) > MAX_BODY:
        raise ValueError("Payload too large")
    return result


def decrypt(compact: bytes, key: jwk.JWK, kid: str, kind: str) -> dict[str, Any]:
    if len(compact) > MAX_BODY:
        raise ValueError("Envelope too large")
    parts = compact.decode("ascii").split(".")
    if len(parts) != 5 or parts[1] or len(parts[0]) > 4096:
        raise ValueError("Invalid compact envelope")
    decoded = [unbase64(part) for part in parts]
    header = loads(decoded[0])
    if set(header) != {"alg", "enc", "epk", "kid", "typ", "cty"}:
        raise ValueError("Invalid protected header")
    if any(header[name] != expected for name, expected in {
        "alg": "ECDH-ES", "enc": "A256GCM", "kid": kid, "typ": kind, "cty": "application/json"
    }.items()):
        raise ValueError("Unexpected protected header")
    if len(decoded[2]) != 12 or len(decoded[4]) != 16:
        raise ValueError("Invalid IV or authentication tag")
    public_key(header["epk"])
    token = jwe.JWE(algs=ALGORITHMS)
    token.deserialize(compact.decode("ascii"))
    token.decrypt(key, max_plaintext=MAX_PLAINTEXT)
    return loads(token.payload)
