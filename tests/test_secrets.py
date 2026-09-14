import os
import tempfile
import unittest
from unittest.mock import patch

from jarvis.collectors.identity.secrets import _private_blocks, audit, fingerprint, scan_file


class SecretScannerSyntaxTests(unittest.TestCase):
    def test_audit_does_not_infer_volume_encryption_or_duplicate_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch("jarvis.collectors.identity.secrets.run.walk", return_value=["/test/key", "/test/key"]), \
                 patch("jarvis.collectors.identity.secrets.run.scan_file", return_value=[
                     ("private key block (encrypted)", "synthetic-key", 1, "low")]), \
                 patch("jarvis.collectors.identity.secrets.run._other_humans", return_value=[]), \
                 patch("jarvis.collectors.identity.secrets.run._world_readable", return_value=False), \
                 patch("jarvis.collectors.identity.secrets.run._git_tracked", return_value=(False, "")), \
                 patch("jarvis.collectors.identity.secrets.run.os.path.expanduser", return_value=directory):
                findings = audit(roots=[directory], deep=True)
        key = next(f for f in findings if "private key block" in f["title"])
        self.assertNotIn("plaintext", key["title"])
        self.assertNotIn("more location", key["title"])
        self.assertNotIn("disk is not encrypted", key["detail"])
        self.assertIn("has not been verified", key["detail"])
        self.assertNotIn("synthetic-key", key["detail"])

    def test_private_key_identity_uses_body_and_ignores_wrapping(self):
        def block(body):
            return f"-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----"
        first = list(_private_blocks(block("YWJj\nZGVm")))[0]
        wrapped = list(_private_blocks(block("YWJjZGVm")))[0]
        other = list(_private_blocks(block("Z2hpamts")))[0]
        self.assertEqual(fingerprint(first[1]), fingerprint(wrapped[1]))
        self.assertNotEqual(fingerprint(first[1]), fingerprint(other[1]))
        self.assertEqual(first[0], "private key block (unencrypted)")

    def test_encrypted_pem_is_not_reported_as_plaintext(self):
        hit = list(_private_blocks(
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nYWJj\n"
            "-----END ENCRYPTED PRIVATE KEY-----"))[0]
        self.assertEqual(hit[0], "private key block (encrypted)")
        self.assertEqual(hit[3], "low")

    def test_header_alone_is_not_a_private_key(self):
        self.assertEqual(self.scan("key.pem", "-----BEGIN PRIVATE KEY-----"), [])

    def test_openssh_cipher_classification(self):
        import base64
        for cipher, expected in ((b"none", "unencrypted"), (b"aes256-ctr", "encrypted")):
            raw = b"openssh-key-v1\0" + len(cipher).to_bytes(4, "big") + cipher
            body = base64.b64encode(raw).decode()
            hit = list(_private_blocks(
                f"-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n"
                "-----END OPENSSH PRIVATE KEY-----"))[0]
            self.assertEqual(hit[0], f"private key block ({expected})")

    def scan(self, name, text):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, name)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(text)
            return [(kind, line) for kind, _value, line, _sev in scan_file(path)]

    def test_quoted_secret_literal_is_detected(self):
        hits = self.scan("settings.ts", 'const config = { apiKey: "a8F2kL9xQ4mN7pR3vT6yW1zC" };\n')
        self.assertEqual(hits, [("generic secret assignment", 1)])

    def test_runtime_expressions_are_not_secret_literals(self):
        hits = self.scan(
            "settings.ts",
            "const config = {\n"
            "  password: credentials.password,\n"
            "  input_tokens: completed.inputTokens,\n"
            "  signing_key: settings.keyForToken(token),\n"
            "};\n",
        )
        self.assertEqual(hits, [])

    def test_environment_variable_names_are_not_values(self):
        hits = self.scan(
            "provider.ts",
            'const config = { webhookSecretEnv: "CARD_ACQUIRER_WEBHOOK_SECRET" };\n',
        )
        self.assertEqual(hits, [])

    def test_storage_namespace_is_not_a_token(self):
        hits = self.scan("oidc.ts", 'const tokenKey = "product.oidc_access.token";\n')
        self.assertEqual(hits, [])

    def test_bare_env_value_is_detected(self):
        hits = self.scan(".env", "SERVICE_SECRET=a8F2kL9xQ4mN7pR3vT6yW1zC\n")
        self.assertEqual(hits, [("generic secret assignment", 1)])

    def test_database_url_placeholder_is_not_a_credential(self):
        hits = self.scan(
            "architecture.md",
            "DATABASE_URL=postgresql://user:password@host:5432/database\n",
        )
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
