
"""Kiem thu PasswordHandler voi database tam (khong dung Vault that).
Chay tu thu muc goc du an: python -m unittest discover -s tests -p test_handler.py -v
"""
import os
import tempfile
import unittest
from unittest.mock import patch

from modules import database as db
from modules import security
from modules.handler import PasswordHandler


class HandlerTests(unittest.TestCase):
    MASTER = "Demo-Master-Password-Only-For-Tests!"

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        db.set_db_path(os.path.join(self.temp_dir.name, "data", "test.db"))
        self.handler = PasswordHandler()

    def tearDown(self):
        self.handler.lock_vault()
        db.set_db_path(db.DEFAULT_DB_PATH)
        self.temp_dir.cleanup()

    def call(self, action, **kwargs):
        return self.handler.handle({"action": action, **kwargs})

    def create_and_unlock(self):
        self.assertTrue(self.call("create_vault", master_password=self.MASTER)["success"])
        self.assertTrue(self.call("unlock_vault", master_password=self.MASTER)["success"])

    def add_demo(self, website="https://example.com", username="demo", password="FakePassword123!"):
        result = self.call("add_password", website=website, username=username,
                           password=password, note="test note")
        self.assertTrue(result["success"], result)
        return result["id"]

    def test_invalid_request_and_unknown_action(self):
        self.assertFalse(self.handler.handle(None)["success"])
        self.assertFalse(self.call("not_supported")["success"])

    def test_vault_starts_locked(self):
        self.assertIsNone(self.handler.key)
        self.assertFalse(self.call("get_passwords")["success"])
        self.assertFalse(self.call("add_password", website="https://a.test",
                                   username="u", password="p")["success"])

    def test_create_unlock_and_reject_wrong_master(self):
        self.assertTrue(self.call("create_vault", master_password=self.MASTER)["success"])
        self.assertFalse(self.call("create_vault", master_password=self.MASTER)["success"])
        self.assertFalse(self.call("unlock_vault", master_password="wrong")["success"])
        self.assertIsNone(self.handler.key)
        self.assertTrue(self.call("unlock_vault", master_password=self.MASTER)["success"])

    def test_empty_master_rejected(self):
        self.assertFalse(self.call("create_vault", master_password="")["success"])
        self.assertFalse(self.call("unlock_vault", master_password="")["success"])

    def test_add_and_list_does_not_expose_password(self):
        self.create_and_unlock()
        account_id = self.add_demo()
        result = self.call("get_passwords")
        self.assertTrue(result["success"])
        self.assertEqual(len(result["accounts"]), 1)
        account = result["accounts"][0]
        self.assertEqual(account["id"], account_id)
        self.assertEqual(account["website"], "https://example.com")
        self.assertEqual(account["username"], "demo")
        self.assertNotIn("password", account)
        self.assertNotIn("encrypted_data", account)
        self.assertNotIn("nonce", account)

    def test_reveal_requires_master_and_returns_only_selected_password(self):
        self.create_and_unlock()
        first_id = self.add_demo(password="TestFirst111!")
        second_id = self.add_demo(website="https://another.test", password="TestSecond222!")
        bad = self.call("reveal_password", id=first_id, master_password="wrong")
        self.assertFalse(bad["success"])
        good = self.call("reveal_password", id=second_id, master_password=self.MASTER)
        self.assertTrue(good["success"])
        self.assertEqual(good["password"], "TestSecond222!")
        self.assertNotIn("accounts", good)

    def test_reveal_invalid_id_and_missing_account(self):
        self.create_and_unlock()
        for invalid in (None, True, 0, -5, "1"):
            self.assertFalse(self.call("reveal_password", id=invalid,
                                       master_password=self.MASTER)["success"])
        self.assertFalse(self.call("reveal_password", id=999,
                                   master_password=self.MASTER)["success"])
        self.assertFalse(self.call("reveal_password", id=1,
                                   master_password="")["success"])

    def test_search_filters_and_hides_password(self):
        self.create_and_unlock()
        self.add_demo(website="https://example.com")
        self.add_demo(website="https://github.com", password="AnotherFakePass!")
        result = self.call("search_password", keyword="GITHUB")
        self.assertTrue(result["success"])
        self.assertEqual(len(result["accounts"]), 1)
        self.assertEqual(result["accounts"][0]["website"], "https://github.com")
        self.assertNotIn("password", result["accounts"][0])
        self.assertEqual(self.call("search_password", keyword="no-match")["accounts"], [])

    def test_add_rejects_bad_fields(self):
        self.create_and_unlock()
        for data in (
            {"website": "", "username": "u", "password": "p"},
            {"website": "https://a.test", "username": None, "password": "p"},
            {"website": "https://a.test", "username": "u", "password": None},
            {"website": "https://a.test", "username": "u", "password": "p", "note": 123},
        ):
            self.assertFalse(self.call("add_password", **data)["success"])
        self.assertEqual(db.get_accounts(), [])

    def test_delete_and_invalid_delete_id(self):
        self.create_and_unlock()
        account_id = self.add_demo()
        self.assertTrue(self.call("delete_password", id=account_id)["success"])
        self.assertFalse(self.call("delete_password", id=account_id)["success"])
        self.assertFalse(self.call("delete_password", id=True)["success"])
        self.assertEqual(db.get_accounts(), [])

    def test_lock_blocks_reveal_and_list(self):
        self.create_and_unlock()
        account_id = self.add_demo()
        self.assertTrue(self.call("lock_vault")["success"])
        self.assertIsNone(self.handler.key)
        self.assertFalse(self.call("get_passwords")["success"])
        self.assertFalse(self.call("reveal_password", id=account_id,
                                   master_password=self.MASTER)["success"])

    def test_update_rejects_invalid_id(self):
        self.create_and_unlock()
        self.assertFalse(self.call("update_password", id=True, password="p")["success"])
        self.assertFalse(self.call("update_password", id=0, password="p")["success"])

    def test_update_dispatch_using_mock(self):
        """Kiem tra Handler chuyen tham so dung; khong chung minh Security update that."""
        self.create_and_unlock()
        account_id = self.add_demo()
        with patch.object(security, "update_password", create=True, return_value=True) as mock_update:
            result = self.call("update_password", id=account_id, password="NewFakePass!")
            self.assertTrue(result["success"])
            mock_update.assert_called_once_with(
                account_id, self.handler.key,
                website=None, username=None, password="NewFakePass!", note=None,
            )

    @unittest.skipUnless(hasattr(security, "update_password"),
                         "Security chua co update_password(): can sua code truoc khi test thuc te")
    def test_update_real_database(self):
        self.create_and_unlock()
        account_id = self.add_demo(password="BeforeFake!")
        result = self.call("update_password", id=account_id, password="AfterFake!")
        self.assertTrue(result["success"], result)
        revealed = self.call("reveal_password", id=account_id,
                             master_password=self.MASTER)
        self.assertEqual(revealed["password"], "AfterFake!")

    def test_duplicate_asks_before_saving(self):
        self.create_and_unlock()
        first_id = self.add_demo(password="OldFake!")
        result = self.call("add_password", website="https://example.com/",
                           username=" DEMO ", password="NewFake!", note="")
        self.assertFalse(result["success"])
        self.assertTrue(result["duplicate"])
        self.assertEqual(result["id"], first_id)
        self.assertIn("cập nhật mật khẩu mới", result["error"])
        self.assertEqual(len(self.call("get_passwords")["accounts"]), 1)
        revealed = self.call("reveal_password", id=first_id,
                             master_password=self.MASTER)
        self.assertEqual(revealed["password"], "OldFake!")

    def test_duplicate_overwrite_updates_password(self):
        self.create_and_unlock()
        first_id = self.add_demo(password="OldFake!")
        result = self.call("add_password", website="https://example.com",
                           username="demo", password="NewFake!", note="",
                           overwrite=True)
        self.assertTrue(result["success"], result)
        self.assertTrue(result["updated"])
        self.assertEqual(result["id"], first_id)
        self.assertEqual(len(self.call("get_passwords")["accounts"]), 1)
        revealed = self.call("reveal_password", id=first_id,
                             master_password=self.MASTER)
        self.assertEqual(revealed["password"], "NewFake!")
        # Ghi chu cu duoc giu khi ghi chu moi de trong.
        self.assertEqual(self.call("get_passwords")["accounts"][0]["note"], "test note")

    def test_same_site_different_username_is_not_duplicate(self):
        self.create_and_unlock()
        self.add_demo(username="alice")
        self.add_demo(username="bob")
        self.assertEqual(len(self.call("get_passwords")["accounts"]), 2)


if __name__ == "__main__":
    unittest.main()
