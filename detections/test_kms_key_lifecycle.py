import json
import unittest
from pathlib import Path

from kms_key_lifecycle import matches

FIXTURES = Path(__file__).parent / "fixtures"
OURS = {
    "arn:aws:kms:us-east-1:455697799770:key/data-cmk-id",
    "arn:aws:kms:us-east-1:455697799770:key/vault-cmk-id",
}


def load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


class KmsKeyLifecycleTests(unittest.TestCase):
    def test_disable_data_cmk_alerts(self):
        self.assertTrue(matches(load("kms_disable_data_cmk.json"), OURS))

    def test_schedule_vault_deletion_alerts(self):
        self.assertTrue(matches(load("kms_schedule_vault_cmk.json"), OURS))

    def test_encrypt_is_noise_and_ignored(self):
        self.assertFalse(matches(load("kms_encrypt.json"), OURS))

    def test_other_account_key_ignored(self):
        self.assertFalse(matches(load("kms_disable_other_account.json"), OURS))


if __name__ == "__main__":
    unittest.main()
