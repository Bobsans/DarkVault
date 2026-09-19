"""Synchronous, token-only HTTP client. No credentials or values are logged."""

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import http.client
import math
import random
import re
import ssl
import threading
import time
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from jwcrypto import jwk
from jwcrypto.common import JWException

from . import _protocol as wire

_READS = {"bucket.get", "bucket.list", "bucket.read", "secret.read", "secret.list", "token.info"}
_OPERATIONS = _READS | {"bucket.create", "bucket.update", "bucket.delete", "secret.create", "secret.update", "secret.set", "secret.delete"}
_ERRORS = {"invalid_request", "invalid_envelope", "unsupported_version", "unknown_key", "request_expired",
           "unauthorized", "forbidden", "not_found", "already_exists", "revision_conflict", "bucket_not_empty",
           "replay_detected", "payload_too_large", "rate_limited", "internal_error", "unavailable",
           "invalid_bucket_name", "invalid_key", "invalid_cursor", "unknown_operation", "revision_exhausted"}


class DarkVaultError(Exception):
    """Safe error metadata; never includes the raw request or server response."""

    def __init__(self, code: str, status: int = 0, request_id: str | None = None):
        self.code = code
        self.status = status
        self.request_id = request_id
        super().__init__(f"DarkVault request failed ({code}).")


def _uuid(value: Any) -> None:
    if not isinstance(value, str):
        raise ValueError("Invalid UUID")
    UUID(value)


def _date(value: Any) -> datetime:
    if not isinstance(value, str) or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|\+00:00)", value) is None:
        raise ValueError("Invalid UTC timestamp")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _revision(value: Any) -> int:
    if type(value) is not int or not 0 <= value <= 9007199254740991:
        raise ValueError("Revision must be an integer between 0 and 9007199254740991")
    return value


def _data(operation: str, data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ValueError("Missing response data")

    def record(item: Any, secret: bool = False, value: bool = False) -> None:
        if not isinstance(item, dict):
            raise ValueError("Invalid record")
        _uuid(item["id"])
        _revision(item["revision"])
        _date(item["createdAt"])
        _date(item["updatedAt"])
        fields = ["key"] if secret else ["name", "description"]
        if secret:
            _uuid(item["bucketId"])
        if value:
            fields.append("value")
        if any(not isinstance(item[f], str) for f in fields):
            raise ValueError("Invalid record fields")

    if operation.endswith(".delete"):
        if data["deleted"] is not True:
            raise ValueError("Invalid deletion result")
    elif operation.endswith(".list"):
        if not isinstance(data["items"], list) or not (data["nextCursor"] is None or isinstance(data["nextCursor"], str)):
            raise ValueError("Invalid page")
        for item in data["items"]:
            record(item, operation == "secret.list")
    elif operation == "bucket.read":
        _uuid(data["bucketId"])
        _revision(data["revision"])
        secrets = data["secrets"]
        if not isinstance(secrets, dict) or any(not isinstance(v, str) for v in secrets.values()):
            raise ValueError("Invalid secret dictionary")
    elif operation == "token.info":
        _uuid(data["id"])
        if not isinstance(data["name"], str) or type(data["allBuckets"]) is not bool:
            raise ValueError("Invalid token metadata")
        for field in ("scopes", "bucketIds", "creatableBucketNames"):
            if not isinstance(data[field], list) or any(not isinstance(x, str) for x in data[field]):
                raise ValueError("Invalid token metadata")
        for bucket in data["bucketIds"]:
            _uuid(bucket)
        if data["expiresAt"] is not None:
            _date(data["expiresAt"])
    else:
        record(data, operation.startswith("secret."), operation == "secret.read")
    return data


class DarkVaultClient:
    """Reuse as a context manager. Calls on one client share a connection and serialize."""

    def __init__(self, server: str, token: str, *, timeout: float = 30,
                 ssl_context: ssl.SSLContext | None = None):
        try:
            if not isinstance(server, str) or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in server):
                raise ValueError()
            url = urlsplit(server if "://" in server else "https://" + server)
            if url.scheme != "https" or not url.hostname or url.username is not None or url.password is not None or url.path not in ("", "/") or url.query or url.fragment:
                raise ValueError()
            self._host, self._port = url.hostname, url.port if url.port is not None else 443
            if not 1 <= self._port <= 65535:
                raise ValueError()
        except (ValueError, TypeError):
            raise ValueError("Use an HTTPS origin without credentials, path, query or fragment") from None
        if not isinstance(token, str) or re.fullmatch(r"dv1_[A-Za-z0-9_-]{60}", token) is None:
            raise ValueError("Invalid DarkVault token format")
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 30:
            raise ValueError("Timeout must be greater than zero and at most 30 seconds")
        self._ssl = ssl_context if ssl_context is not None else ssl.create_default_context()
        if not self._ssl.check_hostname or self._ssl.verify_mode != ssl.CERT_REQUIRED:
            raise ValueError("TLS certificate and hostname verification are required")
        self._token, self._timeout = token, float(timeout)
        self._connection: http.client.HTTPSConnection | None = None
        self._key: dict[str, Any] | None = None
        self._key_until = 0.0
        self._closed = False
        # ponytail: one serialized HTTPS connection; use one client per worker for parallel I/O.
        self._lock = threading.Lock()

    def __enter__(self) -> "DarkVaultClient":
        if self._closed:
            raise DarkVaultError("client_closed")
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def _disconnect(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def close(self) -> None:
        with self._lock:
            self._disconnect()
            self._key, self._token, self._closed = None, "", True

    @staticmethod
    def _remaining(deadline: float) -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        return remaining

    def _http(self, method: str, path: str, body: bytes | None, deadline: float) -> tuple[int, dict[str, str], bytes]:
        remaining = self._remaining(deadline)
        if self._connection is None:
            self._connection = http.client.HTTPSConnection(self._host, self._port, timeout=remaining, context=self._ssl)
        connection = self._connection
        connection.timeout = remaining
        if connection.sock is None:
            connection.connect()
        connection.sock.settimeout(self._remaining(deadline))
        headers = {"Accept": "application/jose" if body is not None else "application/json", "Accept-Encoding": "identity"}
        if body is not None:
            headers.update({"Authorization": "Bearer " + self._token, "Content-Type": "application/jose"})
        connection.request(method, path, body=body, headers=headers)
        response_socket = connection.sock
        response_socket.settimeout(self._remaining(deadline))
        response = connection.getresponse()
        try:
            if response.getheader("Content-Encoding", "identity").lower() != "identity":
                raise ValueError("Compressed responses are not supported")
            if response.length is not None and response.length > wire.MAX_BODY:
                raise ValueError("Response too large")
            chunks: list[bytes] = []
            size = 0
            while not response.isclosed():
                remaining = self._remaining(deadline)
                response_socket.settimeout(remaining)
                chunk = response.read1(min(8192, wire.MAX_BODY + 1 - size))
                if not chunk:
                    break
                size += len(chunk)
                if size > wire.MAX_BODY:
                    raise ValueError("Response too large")
                chunks.append(chunk)
            if response.length not in (None, 0):
                raise http.client.IncompleteRead(b"")
            self._remaining(deadline)
            return response.status, {k.lower(): v for k, v in response.getheaders()}, b"".join(chunks)
        finally:
            response.close()

    def _server_key(self, deadline: float) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        if self._key is not None and time.monotonic() < self._key_until and _date(self._key["notAfter"]) > now:
            return self._key
        status, _, body = self._http("GET", "/api/v1/crypto/key", None, deadline)
        if 300 <= status < 400:
            raise DarkVaultError("redirect_rejected", status)
        if status != 200:
            raise DarkVaultError("key_unavailable", status)
        value = wire.loads(body)
        if type(value["protocolVersion"]) is not int or value["protocolVersion"] != 1 or _date(value["notAfter"]) <= datetime.now(timezone.utc):
            raise ValueError("Invalid server key")
        _uuid(value["serverId"])
        _uuid(value["kid"])
        _date(value["serverTime"])
        wire.public_key(value["publicKey"])
        self._key = value
        self._key_until = time.monotonic() + 300
        return value

    @staticmethod
    def _pause(headers: dict[str, str], attempt: int, deadline: float) -> None:
        delay = 0.2 * (attempt + 1) + random.random() * 0.1
        retry = headers.get("retry-after")
        if retry is not None:
            try:
                delay = float(int(retry)) if retry.isdigit() else (parsedate_to_datetime(retry) - datetime.now(timezone.utc)).total_seconds()
            except (ValueError, TypeError, OverflowError):
                pass
        delay = max(0, delay)
        if not math.isfinite(delay) or delay >= DarkVaultClient._remaining(deadline):
            raise TimeoutError()
        time.sleep(delay)

    def execute(self, operation: str, parameters: dict[str, Any]) -> dict[str, Any]:
        """Execute a data operation; administrative cookie operations are not supported."""
        if not isinstance(operation, str) or operation not in _OPERATIONS or not isinstance(parameters, dict):
            raise ValueError("Unknown data operation or invalid parameters")
        with self._lock:
            if self._closed:
                raise DarkVaultError("client_closed")
            deadline = time.monotonic() + self._timeout
            read, retries, key_retry = operation in _READS, 0, False
            while True:
                request_id: str | None = None
                sent = False
                try:
                    server = self._server_key(deadline)
                    reply = jwk.JWK.generate(kty="EC", crv="P-256")
                    request_id = str(uuid4())
                    payload = {"v": 1, "requestId": request_id, "issuedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                               "serverId": server["serverId"], "audience": "data", "operation": operation,
                               "parameters": parameters, "replyKey": reply.export_public(as_dict=True)}
                    encrypted = wire.encrypt(payload, wire.public_key(server["publicKey"]), server["kid"], "darkvault-request+jwe")
                    self._remaining(deadline)
                    sent = True
                    status, headers, body = self._http("POST", "/api/v1/execute", encrypted, deadline)
                    if 300 <= status < 400:
                        raise DarkVaultError("redirect_rejected", status, request_id)
                    if headers.get("content-type", "").split(";", 1)[0].lower() != "application/jose":
                        if 200 <= status < 300:
                            raise DarkVaultError("unencrypted_response", status, request_id)
                        code = "transport_error"
                        try:
                            candidate = wire.loads(body)["error"]["code"]
                            if isinstance(candidate, str) and candidate in _ERRORS:
                                code = candidate
                        except (ValueError, KeyError, TypeError):
                            pass
                        if status == 400 and code == "unknown_key" and not key_retry:
                            self._key, key_retry = None, True
                            continue
                        if read and retries < 2 and (status == 429 or status >= 500):
                            self._pause(headers, retries, deadline)
                            retries += 1
                            continue
                        raise DarkVaultError(code, status, request_id)
                    response = wire.decrypt(body, reply, request_id, "darkvault-response+jwe")
                    if type(response["v"]) is not int or response["v"] != 1 or type(response["status"]) is not int or response["status"] != status:
                        raise ValueError("Invalid response version or status")
                    for field in ("requestId", "serverId", "audience", "operation"):
                        if response[field] != payload[field]:
                            raise ValueError("Response does not match request")
                    if response["error"] is not None:
                        code = response["error"]["code"]
                        if not isinstance(code, str) or response["data"] is not None or 200 <= status < 300:
                            raise ValueError("Invalid error envelope")
                        raise DarkVaultError(code if code in _ERRORS else "server_error", status, request_id)
                    if not 200 <= status < 300:
                        raise ValueError("Invalid response status")
                    return _data(operation, response["data"])
                except ssl.SSLError:
                    self._disconnect()
                    raise DarkVaultError("outcome_unknown" if sent and not read else "tls_error", request_id=request_id) from None
                except TimeoutError:
                    self._disconnect()
                    raise DarkVaultError("outcome_unknown" if sent and not read else "timeout", request_id=request_id) from None
                except (OSError, http.client.HTTPException):
                    self._disconnect()
                    if read and retries < 2:
                        try:
                            self._pause({}, retries, deadline)
                        except TimeoutError:
                            raise DarkVaultError("timeout", request_id=request_id) from None
                        retries += 1
                        continue
                    raise DarkVaultError("outcome_unknown" if sent and not read else "unavailable", request_id=request_id) from None
                except (ValueError, KeyError, TypeError, JWException, OverflowError):
                    self._disconnect()
                    raise DarkVaultError("invalid_response" if sent else "invalid_request_or_key", request_id=request_id) from None

    def add_bucket(self, name: str, description: str = "") -> dict[str, Any]:
        return self.execute("bucket.create", {"name": name, "description": description})

    def get_bucket(self, bucket: str) -> dict[str, Any]:
        return self.execute("bucket.get", {"bucket": bucket})

    def list_buckets(self, *, cursor: str | None = None, limit: int = 100) -> dict[str, Any]:
        return self.execute("bucket.list", {"cursor": cursor, "limit": limit})

    def read_bucket_snapshot(self, bucket: str) -> dict[str, Any]:
        return self.execute("bucket.read", {"bucket": bucket})

    def read_bucket(self, bucket: str) -> dict[str, str]:
        return self.read_bucket_snapshot(bucket)["secrets"]

    def update_bucket(self, bucket: str, description: str, expected_revision: int) -> dict[str, Any]:
        return self.execute("bucket.update", {"bucket": bucket, "description": description, "expectedRevision": _revision(expected_revision)})

    def delete_bucket(self, bucket: str, expected_revision: int, *, recursive: bool = False) -> None:
        self.execute("bucket.delete", {"bucket": bucket, "expectedRevision": _revision(expected_revision), "recursive": recursive})

    def add_secret(self, bucket: str, key: str, value: str) -> dict[str, Any]:
        return self.execute("secret.create", {"bucket": bucket, "key": key, "value": value})

    def read_secret(self, bucket: str, key: str) -> dict[str, Any]:
        return self.execute("secret.read", {"bucket": bucket, "key": key})

    def list_secrets(self, bucket: str, *, cursor: str | None = None, limit: int = 100) -> dict[str, Any]:
        return self.execute("secret.list", {"bucket": bucket, "cursor": cursor, "limit": limit})

    def update_secret(self, bucket: str, key: str, value: str, expected_revision: int) -> dict[str, Any]:
        return self.execute("secret.update", {"bucket": bucket, "key": key, "value": value, "expectedRevision": _revision(expected_revision)})

    def set_secret(self, bucket: str, key: str, value: str, expected_revision: int = 0) -> dict[str, Any]:
        return self.execute("secret.set", {"bucket": bucket, "key": key, "value": value, "expectedRevision": _revision(expected_revision)})

    def delete_secret(self, bucket: str, key: str, expected_revision: int) -> None:
        self.execute("secret.delete", {"bucket": bucket, "key": key, "expectedRevision": _revision(expected_revision)})

    def get_token_info(self) -> dict[str, Any]:
        return self.execute("token.info", {})
