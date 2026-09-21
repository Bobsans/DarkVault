from datetime import datetime, timedelta, timezone
import json
import http.client
import os
from pathlib import Path
import ssl
import time
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from jwcrypto import jwk
from jwcrypto.common import JWException

from darkvault import DarkVaultClient, DarkVaultError, load_configuration
from darkvault import _protocol as wire

ROOT = Path(__file__).resolve().parents[3]
TOKEN = "dv1_" + "A" * 60


class ProtocolTests(unittest.TestCase):
    def test_dotnet_fixture_and_tampering(self):
        fixture = json.loads((ROOT / "tests/fixtures/jwe.json").read_text(encoding="utf-8"))
        key = jwk.JWK(**fixture["jwk"])
        expected = json.loads(fixture["plaintext"])
        actual = wire.decrypt(fixture["compact"].encode(), key, fixture["kid"], fixture["type"])
        self.assertEqual(expected, actual)
        encrypted = wire.encrypt(expected, wire.public_key(key.export_public(as_dict=True)), fixture["kid"], fixture["type"])
        self.assertEqual(expected, wire.decrypt(encrypted, key, fixture["kid"], fixture["type"]))
        parts = encrypted.decode().split(".")
        parts[4] = "A" * 22
        with self.assertRaises((ValueError, JWException)):
            wire.decrypt(".".join(parts).encode(), key, fixture["kid"], fixture["type"])
        with self.assertRaises(ValueError):
            wire.decrypt(encrypted, key, "wrong-request", fixture["type"])
        with self.assertRaises(ValueError):
            wire.decrypt(encrypted, key, fixture["kid"], "darkvault-request+jwe")

    def test_strict_json_keys_and_sizes(self):
        for body in [b'{"a":1,"a":2}', b'{"a":1,"\\u0061":2}', b'{"x":NaN}',
                     b'{"x":"\\ud800"}', b'{"x":' + b'[' * 17 + b'0' + b']' * 17 + b'}',
                     b'x' * (wire.MAX_PLAINTEXT + 1), b'null']:
            with self.subTest(length=len(body)), self.assertRaises(ValueError):
                wire.loads(body)
        public = jwk.JWK.generate(kty="EC", crv="P-256").export_public(as_dict=True)
        with self.assertRaises(ValueError):
            wire.public_key({**public, "d": "private"})
        with self.assertRaises(ValueError):
            wire.public_key({**public, "crv": "P-384"})
        with self.assertRaises(ValueError):
            wire.public_key({**public, "x": "A" * 43, "y": "A" * 43})


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.key = jwk.JWK.generate(kty="EC", crv="P-256")
        self.discovery = {"protocolVersion": 1, "serverId": str(uuid4()), "serverTime": self.now(),
                          "kid": str(uuid4()), "publicKey": self.key.export_public(as_dict=True),
                          "notAfter": self.now(timedelta(hours=1))}
        self.data = {"bucketId": str(uuid4()), "revision": 2, "secrets": {"Unicode": "秘密\nvalue", "Empty": ""}}
        self.requests = []
        self.status = 200
        self.error = None
        self.transform = lambda response: response
        self.client = DarkVaultClient("https://vault.example.com", TOKEN)
        self.addCleanup(self.client.close)

    @staticmethod
    def now(delta=timedelta()):
        return (datetime.now(timezone.utc) + delta).isoformat().replace("+00:00", "Z")

    def respond(self, method, path, body, deadline):
        if method == "GET":
            self.assertEqual(path, "/api/v1/crypto/key")
            return 200, {"content-type": "application/json"}, wire.dumps(self.discovery)
        request = wire.decrypt(body, self.key, self.discovery["kid"], "darkvault-request+jwe")
        self.requests.append(request)
        response = {k: request[k] for k in ("v", "requestId", "serverId", "audience", "operation")}
        response.update(status=self.status, data=self.data if self.error is None else None, error=self.error)
        response = self.transform(response)
        encrypted = wire.encrypt(response, wire.public_key(request["replyKey"]), request["requestId"], "darkvault-response+jwe")
        return self.status, {"content-type": "application/jose"}, encrypted

    def test_connection_strings(self):
        for host in ("vault.example.com", "localhost:8443", "[::1]:8443"):
            with DarkVaultClient.from_url(f"https://{TOKEN}@{host}/qa") as client:
                self.assertEqual(client.default_bucket, "qa")
                self.assertNotIn(TOKEN, client._host)
                with patch.object(client, "_http", side_effect=self.respond):
                    self.assertEqual(client.read_bucket(), self.data["secrets"])
                    client.read_bucket("other")
                self.assertEqual(self.requests[-2]["parameters"], {"bucket": "qa"})
                self.assertEqual(self.requests[-1]["parameters"], {"bucket": "other"})
        for raw in ['http://{token}@vault.example.com/qa', 'https://vault.example.com/qa', 'https://{token}:password@vault.example.com/qa', 'https://{token}@vault.example.com', 'https://{token}@vault.example.com/', 'https://{token}@vault.example.com/qa/', 'https://{token}@vault.example.com/a/../qa', 'https://{token}@vault.example.com/qa?x=1', 'https://{token}@vault.example.com/qa#x', 'https://{token}@vault.example.com/qa\n', 'https://{token}@vault.example.com:0/qa', 'https://{token}@vault.example.com:65536/qa', 'https://{token}@[bad/qa', 'https://{token}@/qa', 'https://{token}@vault.example.com/UPPER', 'https://{token}@vault.example.com/%71a', 'https://bad@vault.example.com/qa']:
            with self.assertRaises(ValueError) as error:
                DarkVaultClient.from_url(raw.replace("{token}", TOKEN))
            self.assertNotIn(TOKEN, str(error.exception))
        with self.assertRaises(ValueError):
            self.client.read_bucket()

    def test_load_configuration_closes_client_on_success_and_failure(self):
        url = f"https://{TOKEN}@vault.example.com/qa"
        for fail in (False, True):
            client = DarkVaultClient.from_url(url)
            self.addCleanup(client.close)
            with patch.object(DarkVaultClient, "from_url", return_value=client), patch.object(client, "_http", side_effect=self.respond):
                if fail:
                    self.error = {"code": "forbidden"}
                    self.status = 403
                    with self.assertRaises(DarkVaultError):
                        load_configuration(url)
                else:
                    self.assertEqual(load_configuration(url), self.data["secrets"])
            self.assertTrue(client._closed)

    def test_bucket_reads_and_key_cache(self):
        with patch.object(self.client, "_http", side_effect=self.respond) as transport:
            self.assertEqual(self.client.read_bucket("qa"), self.data["secrets"])
            self.client.read_bucket_snapshot("qa")
        self.assertEqual(transport.call_count, 3)
        self.assertNotEqual(self.requests[0]["requestId"], self.requests[1]["requestId"])
        self.assertNotEqual(self.requests[0]["replyKey"], self.requests[1]["replyKey"])
        self.assertTrue(all(r["parameters"] == {"bucket": "qa"} for r in self.requests))

    def test_response_identity_and_required_fields(self):
        for field in ("v", "requestId", "serverId", "audience", "operation", "status"):
            with self.subTest(field=field):
                self.transform = lambda response, name=field: {**response, name: "wrong"}
                with patch.object(self.client, "_http", side_effect=self.respond), self.assertRaises(DarkVaultError) as error:
                    self.client.read_bucket("qa")
                self.assertEqual(error.exception.code, "invalid_response")
        self.transform = lambda response: {**response, "data": {"secrets": {"K": "V"}}}
        with patch.object(self.client, "_http", side_effect=self.respond), self.assertRaises(DarkVaultError):
            self.client.read_bucket("qa")

    def test_encrypted_error_has_safe_metadata(self):
        self.status, self.error = 403, {"code": "forbidden", "message": "sensitive server diagnostic"}
        with patch.object(self.client, "_http", side_effect=self.respond), self.assertRaises(DarkVaultError) as failure:
            self.client.read_bucket("qa")
        self.assertEqual(failure.exception.status, 403)
        self.assertEqual(failure.exception.code, "forbidden")
        self.assertEqual(failure.exception.request_id, self.requests[-1]["requestId"])
        self.assertNotIn("sensitive", str(failure.exception))
        self.assertNotIn(TOKEN, repr(failure.exception))
        self.assertNotIn(TOKEN, repr(self.client))

    def test_plain_success_and_redirect_are_rejected(self):
        for status in (200, 302):
            def response(method, path, body, deadline):
                if method == "GET":
                    return self.respond(method, path, body, deadline)
                return status, {"content-type": "application/json", "location": "https://other.example.com"}, b'{"value":"plaintext"}'
            with patch.object(self.client, "_http", side_effect=response) as transport, self.assertRaises(DarkVaultError) as failure:
                self.client.read_bucket("qa")
            self.assertEqual(failure.exception.code, "unencrypted_response" if status == 200 else "redirect_rejected")
            self.assertLessEqual(transport.call_count, 2)

    def test_mutations_are_not_retried_on_network_failure(self):
        def response(method, path, body, deadline):
            if method == "GET":
                return self.respond(method, path, body, deadline)
            raise OSError("raw network diagnostics")
        with patch.object(self.client, "_http", side_effect=response) as transport, self.assertRaises(DarkVaultError) as failure:
            self.client.add_secret("qa", "key", "value")
        self.assertEqual(failure.exception.code, "outcome_unknown")
        self.assertEqual(transport.call_count, 2)

    def test_read_retry_and_retry_after_budget(self):
        posts = 0
        def response(method, path, body, deadline):
            nonlocal posts
            if method == "POST":
                posts += 1
                if posts <= 2:
                    return 429, {"retry-after": "0"}, b'{"error":{"code":"rate_limited"}}'
            return self.respond(method, path, body, deadline)
        with patch.object(self.client, "_http", side_effect=response):
            self.assertEqual(self.client.read_bucket("qa"), self.data["secrets"])
        self.assertEqual(posts, 3)
        with self.assertRaises(TimeoutError):
            self.client._pause({"retry-after": "3600"}, 0, time.monotonic() + 1)

    def test_explicit_unknown_key_refreshes_once(self):
        posts = 0
        def response(method, path, body, deadline):
            nonlocal posts
            if method == "POST":
                posts += 1
                if posts == 1:
                    return 400, {}, b'{"error":{"code":"unknown_key"}}'
            return self.respond(method, path, body, deadline)
        with patch.object(self.client, "_http", side_effect=response) as transport:
            self.client.read_bucket("qa")
        self.assertEqual(transport.call_count, 4)
        self.assertEqual(posts, 2)

    def test_closed_client_and_invalid_inputs(self):
        self.client.close()
        with self.assertRaises(DarkVaultError):
            self.client.read_bucket("qa")
        for server in ("http://vault.example.com", "https://user:password@vault.example.com", "https://vault.example.com/path", "https://vault.example.com?q=a", "https://vault.example.com:0"):
            with self.assertRaises(ValueError):
                DarkVaultClient(server, TOKEN)
        with self.assertRaises(ValueError):
            DarkVaultClient("https://vault.example.com", "invalid")
        insecure = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        insecure.check_hostname = False
        with self.assertRaises(ValueError):
            DarkVaultClient("https://vault.example.com", TOKEN, ssl_context=insecure)

    def test_connection_close_after_complete_body(self):
        connection, response, socket = Mock(), Mock(), Mock()
        connection.sock = socket
        connection.getresponse.return_value = response
        self.client._connection = connection
        response.getheader.return_value = "identity"
        response.getheaders.return_value = [("Content-Type", "application/json")]
        response.status, response.length = 200, 2
        response.isclosed.side_effect = [False, True]
        def read(size):
            response.length = 0
            connection.sock = None
            socket.settimeout.side_effect = OSError("closed socket")
            return b"{}"
        response.read1.side_effect = read
        result = self.client._http("GET", "/api/v1/crypto/key", None, time.monotonic() + 1)
        self.assertEqual(result[2], b"{}")
        self.assertEqual(response.read1.call_count, 1)
        self.assertNotIn("Authorization", connection.request.call_args.kwargs["headers"])

    def test_transport_rejects_oversized_and_incomplete_bodies(self):
        for length, expected in ((wire.MAX_BODY + 1, ValueError), (20, http.client.IncompleteRead)):
            connection, response = Mock(), Mock()
            connection.getresponse.return_value = response
            self.client._connection = connection
            response.length = length
            response.getheader.return_value = "identity"
            response.isclosed.return_value = False
            response.read1.return_value = b""
            with self.subTest(length=length), self.assertRaises(expected):
                self.client._http("GET", "/api/v1/crypto/key", None, time.monotonic() + 1)
            if length > wire.MAX_BODY:
                response.read1.assert_not_called()


@unittest.skipUnless(os.environ.get("DARKVAULT_ACCEPTANCE"), "Requires the local acceptance server")
class LiveTests(unittest.TestCase):
    def test_all_data_operations_against_dotnet(self):
        descriptor = json.loads(Path(os.environ["DARKVAULT_ACCEPTANCE"]).read_text(encoding="utf-8"))
        self.assertTrue(descriptor["url"].startswith("https://127.0.0.1:"))
        context = ssl.create_default_context(cafile=descriptor["ca"])
        token = Path(descriptor["tokenFile"]).read_text(encoding="utf-8").strip()
        name = "python_" + uuid4().hex
        with DarkVaultClient.from_url(descriptor["url"].replace("https://", "https://" + token + "@") + "/" + name, ssl_context=context) as vault:
            bucket = vault.add_bucket(name, "Python acceptance")
            self.assertEqual(vault.get_bucket(name)["id"], bucket["id"])
            bucket = vault.update_bucket(name, "Updated", bucket["revision"])
            self.assertEqual(bucket["description"], "Updated")
            renamed = vault.rename_bucket(name, name + "-renamed", bucket["revision"])
            self.assertEqual(renamed["id"], bucket["id"])
            self.assertEqual(vault.get_bucket(name + "-renamed")["description"], "Updated")
            bucket = vault.rename_bucket(name + "-renamed", name, renamed["revision"])
            item = vault.add_secret(name, "ConnectionStrings:Main", "秘密\nvalue")
            self.assertEqual(vault.read_secret(name, item["key"])["value"], "秘密\nvalue")
            item = vault.update_secret(name, item["key"], "new", item["revision"])
            with self.assertRaises(DarkVaultError) as conflict:
                vault.set_secret(name, item["key"], "must not overwrite", 0)
            self.assertEqual((conflict.exception.code, conflict.exception.status), ("revision_conflict", 409))
            item = vault.set_secret(name, item["key"], "", item["revision"])
            second = vault.set_secret(name, "Other", "second")
            self.assertEqual(vault.read_bucket(), {"ConnectionStrings:Main": "", "Other": "second"})
            first = vault.list_secrets(name, limit=1)
            self.assertIsNotNone(first["nextCursor"])
            last = vault.list_secrets(name, cursor=first["nextCursor"], limit=1)
            self.assertEqual(len(last["items"]), 1)
            self.assertIsNone(last["nextCursor"])
            self.assertNotIn("value", first["items"][0])
            self.assertIn("items", vault.list_buckets(limit=1))
            self.assertTrue(vault.get_token_info()["allBuckets"])
            vault.delete_secret(name, second["key"], second["revision"])
            snapshot = vault.read_bucket_snapshot(name)
            with self.assertRaises(DarkVaultError) as nonempty:
                vault.delete_bucket(name, snapshot["revision"])
            self.assertEqual(nonempty.exception.code, "bucket_not_empty")
            vault.add_secret(name, "Redis:Port", 6379)
            flag = vault.add_secret(name, "Redis:Enabled", False)
            vault.add_secret(name, "Redis:Optional", None)
            self.assertEqual(vault.read_secret(name, "Redis:Port")["type"], "number")
            self.assertIs(vault.read_typed_secret(name, flag["key"])["value"], False)
            self.assertEqual(vault.read_bucket(name)["Redis:Optional"], "null")
            self.assertEqual(vault.read_configuration(name)["Redis"]["Port"], 6379)
            config = load_configuration(descriptor["url"].replace("https://", "https://" + token + "@") + "/" + name, ssl_context=context)
            self.assertEqual(config["Redis"]["Port"], 6379)
            self.assertIsNone(config["Redis"]["Optional"])
            vault.update_secret(name, flag["key"], True, flag["revision"])
            self.assertIs(vault.read_typed_bucket(name)[flag["key"]], True)
            vault.delete_bucket(name, vault.get_bucket(name)["revision"], recursive=True)
            with self.assertRaises(DarkVaultError) as missing:
                vault.get_bucket(name)
            self.assertEqual(missing.exception.status, 404)
        with DarkVaultClient(descriptor["url"], TOKEN, ssl_context=context) as invalid:
            with self.assertRaises(DarkVaultError) as denied:
                invalid.get_token_info()
            self.assertEqual((denied.exception.code, denied.exception.status), ("unauthorized", 401))
        with DarkVaultClient(descriptor["url"], token) as untrusted:
            with self.assertRaises(DarkVaultError) as trust:
                untrusted.get_token_info()
            self.assertEqual(trust.exception.code, "tls_error")


if __name__ == "__main__":
    unittest.main()
