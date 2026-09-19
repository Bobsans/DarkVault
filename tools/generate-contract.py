"""Generate the language-neutral OpenAPI contract without build dependencies."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
S = {"type": "string"}
UUID = {"type": "string", "format": "uuid"}
DATE = {"type": "string", "format": "date-time"}
REV = {"type": "integer", "minimum": 0, "maximum": 9007199254740991}
BOOL = {"type": "boolean"}
SCOPES = ["secret:read", "secret:write", "secret:delete", "secret:list", "bucket:create", "bucket:read", "bucket:list", "bucket:delete", "bucket:write"]

def obj(properties, required=None):
    return {"type": "object", "properties": properties, "required": list(properties) if required is None else required, "additionalProperties": False}

def array(items):
    return {"type": "array", "items": items}

def nullable(schema):
    return {"anyOf": [schema, {"type": "null"}]}

def ref(name):
    return {"$ref": "#/components/schemas/" + name}

def page(item):
    return obj({"items": array(item), "nextCursor": nullable(S)})

schemas = {
    "PublicKey": obj({"kty": {"const": "EC"}, "crv": {"const": "P-256"}, "x": S, "y": S}),
    "Bucket": obj({"id": UUID, "name": S, "description": S, "revision": REV, "createdAt": DATE, "updatedAt": DATE}),
    "SecretMetadata": obj({"id": UUID, "bucketId": UUID, "key": S, "revision": REV, "createdAt": DATE, "updatedAt": DATE}),
    "TokenInfo": obj({"id": UUID, "name": S, "scopes": array({"enum": SCOPES}), "bucketIds": array(UUID), "allBuckets": BOOL, "creatableBucketNames": array(S), "expiresAt": nullable(DATE)}),
    "Error": obj({"code": S, "message": S}),
    "BucketSnapshot": obj({"bucketId": UUID, "revision": REV, "secrets": {"type": "object", "additionalProperties": S}}),
    "CryptoKey": obj({"protocolVersion": {"const": 1}, "serverId": UUID, "serverTime": DATE, "kid": UUID, "publicKey": ref("PublicKey"), "notAfter": DATE, "limits": obj({"maxBodyBytes": REV, "maxPlaintextBytes": REV})}),
    "JweCompact": {"type": "string", "maxLength": 2097152, "description": "ECDH-ES/P-256/A256GCM compact JWE; plaintext schemas below are not sent unencrypted.", "pattern": "^[A-Za-z0-9_-]+\\.\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]+$"},
    "PageParameters": obj({"cursor": nullable(S), "limit": {"type": "integer", "minimum": 1, "maximum": 200}}, []),
}
schemas["Secret"] = obj({**schemas["SecretMetadata"]["properties"], "value": S})
schemas["TokenRecord"] = obj({"info": ref("TokenInfo"), "createdAt": DATE, "revokedAt": nullable(DATE), "lastUsedAt": nullable(DATE)})
schemas["Audit"] = obj({"time": DATE, "principal": S, "operation": S, "bucketId": nullable(UUID), "secretId": nullable(UUID), "requestId": UUID, "result": S})
listing = schemas["PageParameters"]["properties"]
operations = {
    "bucket.create": (obj({"name": S, "description": S}, ["name"]), ref("Bucket")),
    "bucket.get": (obj({"bucket": S}), ref("Bucket")),
    "bucket.list": (ref("PageParameters"), page(ref("Bucket"))),
    "bucket.read": (obj({"bucket": S}), ref("BucketSnapshot")),
    "bucket.update": (obj({"bucket": S, "description": S, "expectedRevision": REV}), ref("Bucket")),
    "bucket.delete": (obj({"bucket": S, "expectedRevision": REV, "recursive": BOOL}, ["bucket", "expectedRevision"]), obj({"deleted": {"const": True}})),
    "secret.create": (obj({"bucket": S, "key": S, "value": S}), ref("SecretMetadata")),
    "secret.read": (obj({"bucket": S, "key": S}), ref("Secret")),
    "secret.list": (obj({"bucket": S, **listing}, ["bucket"]), page(ref("SecretMetadata"))),
    "secret.update": (obj({"bucket": S, "key": S, "value": S, "expectedRevision": REV}), ref("SecretMetadata")),
    "secret.set": (obj({"bucket": S, "key": S, "value": S, "expectedRevision": REV}), ref("SecretMetadata")),
    "secret.delete": (obj({"bucket": S, "key": S, "expectedRevision": REV}), obj({"deleted": {"const": True}})),
    "token.info": (obj({}), ref("TokenInfo")),
    "token.create": (obj({"name": S, "scopes": array({"enum": SCOPES}), "bucketIds": array(UUID), "allBuckets": BOOL, "creatableBucketNames": array(S), "expiresAt": nullable(DATE)}, ["name", "scopes", "bucketIds", "creatableBucketNames"]), obj({"metadata": ref("TokenRecord"), "token": {"type": "string", "pattern": "^dv1_[A-Za-z0-9_-]{60}$"}})),
    "token.list": (ref("PageParameters"), page(ref("TokenRecord"))),
    "token.revoke": (obj({"id": UUID}), obj({"revoked": {"const": True}})),
    "audit.list": (ref("PageParameters"), page(ref("Audit"))),
}
data_operations = list(operations)[:13]
admin_operations = [o for o in operations if o != "token.info"]
for operation, (parameters, result) in operations.items():
    schemas[operation + ".Request"] = obj({"v": {"const": 1}, "requestId": UUID, "issuedAt": DATE, "serverId": UUID, "audience": {"enum": ["data", "admin"]}, "operation": {"const": operation}, "parameters": parameters, "replyKey": ref("PublicKey")})
    schemas[operation + ".Response"] = obj({"v": {"const": 1}, "requestId": UUID, "serverId": UUID, "audience": {"enum": ["data", "admin"]}, "operation": {"const": operation}, "status": {"type": "integer"}, "data": nullable(result), "error": nullable(ref("Error"))})

def execute(admin):
    names = admin_operations if admin else data_operations
    return {"post": {"operationId": "adminExecute" if admin else "execute", "security": [{"AdminSession": [], "Csrf": []}] if admin else [{"BearerToken": []}],
        "requestBody": {"required": True, "content": {"application/jose": {"schema": ref("JweCompact")}}},
        "x-decrypted-request": {"oneOf": [ref(o + ".Request") for o in names]},
        "x-decrypted-response": {"oneOf": [ref(o + ".Response") for o in names]},
        "responses": {"200": {"description": "Encrypted result", "content": {"application/jose": {"schema": ref("JweCompact")}}}, "201": {"description": "Encrypted creation result"}, "default": {"description": "Encrypted application error, or non-secret JSON error before envelope validation"}}}}

paths = {"/api/v1/execute": execute(False), "/admin/api/v1/execute": execute(True),
    "/api/v1/crypto/key": {"get": {"operationId": "getCryptoKey", "responses": {"200": {"description": "Current server public key", "content": {"application/json": {"schema": ref("CryptoKey")}}}}}},
    "/admin/api/v1/session": {"get": {"operationId": "getAdminSession", "responses": {"200": {"description": "Authentication state and CSRF token", "content": {"application/json": {"schema": obj({"authenticated": BOOL, "csrfToken": S})}}}}}}}
for name, fields in {"login": {"username": S, "password": S}, "logout": {}, "password": {"currentPassword": S, "newPassword": S}}.items():
    paths["/admin/" + name] = {"post": {"operationId": "admin" + name.title(), "security": [{"Csrf": []}] if name == "login" else [{"AdminSession": [], "Csrf": []}], "requestBody": {"required": True, "content": {"application/json": {"schema": obj(fields)}}}, "responses": {"200": {"description": "Completed"}, "400": {"description": "Invalid input or CSRF"}, "401": {"description": "Authentication required"}}}}
document = {"openapi": "3.1.0", "info": {"title": "DarkVault", "version": "1.0.0", "description": "HTTPS is mandatory. See protocol.md for JWE and authorization requirements."}, "paths": paths,
    "components": {"securitySchemes": {"BearerToken": {"type": "http", "scheme": "bearer"}, "AdminSession": {"type": "apiKey", "in": "cookie", "name": "__Host-DarkVault"}, "Csrf": {"type": "apiKey", "in": "header", "name": "X-CSRF-Token"}}, "schemas": schemas}}
(ROOT / "docs" / "openapi.json").write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(f"Generated {len(operations)} operation contracts.")
