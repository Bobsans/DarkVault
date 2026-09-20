"""Explicit scalar types and deterministic object-only configuration paths."""

import json
import math
from typing import Any

SecretScalar = str | int | float | bool | None
SECRET_TYPES = {"string", "number", "boolean", "null"}


def encode_scalar(value: SecretScalar) -> dict[str, str]:
    if isinstance(value, str):
        return {"value": value, "type": "string"}
    if value is None:
        return {"value": "null", "type": "null"}
    if type(value) is bool:
        return {"value": "true" if value else "false", "type": "boolean"}
    if type(value) in (int, float):
        try:
            number = float(value)
            if math.isfinite(number) and (not number.is_integer() or abs(value) <= 9007199254740991):
                return {"value": json.dumps(value, allow_nan=False), "type": "number"}
        except (ValueError, OverflowError):
            pass
    raise ValueError("Secret values must be strings, finite interoperable numbers, booleans, or null")


def parse_scalar(value: str, secret_type: str = "string") -> SecretScalar:
    if secret_type == "string":
        return value
    try:
        parsed = json.loads(value)
        encoded = encode_scalar(parsed)
        if encoded["type"] == secret_type:
            return parsed
    except (ValueError, TypeError):
        pass
    raise ValueError("Invalid secret type or scalar value")


def typed_secrets(snapshot: dict[str, Any]) -> dict[str, SecretScalar]:
    types = snapshot.get("types", {})
    if types is None:
        types = {}
    if not isinstance(types, dict) or any(key not in snapshot["secrets"] for key in types):
        raise ValueError("Invalid secret type map")
    return {key: parse_scalar(value, types.get(key, "string")) for key, value in snapshot["secrets"].items()}


def build_configuration(values: dict[str, SecretScalar], nested: bool = True) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values.items():
        encode_scalar(value)
        parts: list[str] = []
        part = ""
        escaped = False
        if nested:
            for ch in key:
                if escaped:
                    if ch not in (":", "\\"):
                        raise ValueError("Invalid configuration path escape")
                    part += ch
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == ":":
                    parts.append(part)
                    part = ""
                else:
                    part += ch
            parts.append(part)
            if escaped or len(parts) > 16 or any(not p for p in parts):
                raise ValueError("Invalid configuration path")
        else:
            parts = [key]
        parent = result
        for segment in parts[:-1]:
            if segment not in parent:
                parent[segment] = {}
            if not isinstance(parent[segment], dict):
                raise ValueError("Configuration paths conflict")
            parent = parent[segment]
        if parts[-1] in parent:
            raise ValueError("Configuration paths conflict")
        parent[parts[-1]] = value
    return result
