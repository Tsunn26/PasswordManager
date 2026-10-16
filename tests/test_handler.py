
"""Kiem thu modules/handler.py.

Chay:
python -m unittest discover -s tests -v
"""

import os
import tempfile
import unittest

from modules import database as db
from modules.handler import PasswordHandler


class HandlerTests(unittest.TestCase):

    # Tao database tam thoi cho moi bai test.
    # Dam bao khong anh huong den mat khau that.
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

        db.set_db_path(
            os.path.join(self.tmp.name, "test.db")
        )

        self.handler = PasswordHandler()

    # Khoi phuc duong dan database mac dinh.
    # Xoa du lieu kiem thu sau moi test.
    def tearDown(self):
        self.handler.lock_vault()
        db.set_db_path(db.DEFAULT_DB_PATH)
        self.tmp.cleanup()

    # Test 1: Tao Vault moi bang Master Password.
    def test_create_vault(self):
        result = self.handler.handle({
            "action": "create_vault",
            "master_password": "Master123!"
        })

        self.assertTrue(result["success"])
        self.assertTrue(db.vault_exists())

    # Test 2: Mo khoa Vault voi Master Password dung.
    def test_unlock_vault(self):
        self.handler.handle({
            "action": "create_vault",
            "master_password": "Master123!"
        })

        result = self.handler.handle({
            "action": "unlock_vault",
            "master_password": "Master123!"
        })

        self.assertTrue(result["success"])
        self.assertIsNotNone(self.handler.key)

    # Test 3: Tu choi Master Password sai.
    def test_wrong_master_password(self):
        self.handler.handle({
            "action": "create_vault",
            "master_password": "Correct123!"
        })

        result = self.handler.handle({
            "action": "unlock_vault",
            "master_password": "Wrong123!"
        })

        self.assertFalse(result["success"])
        self.assertIsNone(self.handler.key)

    # Test 4: Khoa Vault va chan truy cap.
    def test_lock_vault(self):
        self.create_and_unlock()

        result = self.handler.handle({
            "action": "lock_vault"
        })

        self.assertTrue(result["success"])
        self.assertIsNone(self.handler.key)

        result = self.handler.handle({
            "action": "get_passwords"
        })

        self.assertFalse(result["success"])

    # Test 5: Them tai khoan va giai ma du lieu.
    def test_add_and_get_password(self):
        self.create_and_unlock()

        result = self.handler.handle({
            "action": "add_password",
            "website": "https://github.com",
            "username": "user123",
            "password": "Password123!",
            "note": "GitHub account"
        })

        self.assertTrue(result["success"])
        self.assertIsInstance(result["id"], int)

        result = self.handler.handle({
            "action": "get_passwords"
        })

        self.assertTrue(result["success"])
        self.assertEqual(len(result["accounts"]), 1)
        self.assertEqual(
            result["accounts"][0]["username"],
            "user123"
        )
        self.assertEqual(
            result["accounts"][0]["password"],
            "Password123!"
        )

    # Test 6: Cap nhat mat khau cua tai khoan.
    def test_update_password(self):
        self.create_and_unlock()

        added = self.add_sample_account()

        result = self.handler.handle({
            "action": "update_password",
            "id": added["id"],
            "password": "NewPassword456!"
        })

        self.assertTrue(result["success"])

        accounts = self.handler.handle({
            "action": "get_passwords"
        })["accounts"]

        self.assertEqual(
            accounts[0]["password"],
            "NewPassword456!"
        )
        self.assertEqual(
            accounts[0]["username"],
            "user123"
        )

    # Test 7: Xoa tai khoan theo ID.
    def test_delete_password(self):
        self.create_and_unlock()

        added = self.add_sample_account()

        result = self.handler.handle({
            "action": "delete_password",
            "id": added["id"]
        })

        self.assertTrue(result["success"])

        accounts = self.handler.handle({
            "action": "get_passwords"
        })["accounts"]

        self.assertEqual(accounts, [])

    # Test 8: Tim kiem tai khoan theo website.
    def test_search_password(self):
        self.create_and_unlock()
        self.add_sample_account()

        result = self.handler.handle({
            "action": "search_password",
            "keyword": "github"
        })

        self.assertTrue(result["success"])
        self.assertEqual(len(result["accounts"]), 1)
        self.assertEqual(
            result["accounts"][0]["website"],
            "https://github.com"
        )

    # Test 9: Khong cho phep them tai khoan khi Vault khoa.
    def test_access_when_locked(self):
        result = self.handler.handle({
            "action": "add_password",
            "website": "https://github.com",
            "username": "user123",
            "password": "Password123!"
        })

        self.assertFalse(result["success"])

    # Test 10: Xu ly action khong hop le.
    def test_invalid_action(self):
        result = self.handler.handle({
            "action": "unknown_action"
        })

        self.assertFalse(result["success"])

    # Ham ho tro: Tao Vault va mo khoa.
    # Dung lai trong nhieu bai test de tranh lap code.
    def create_and_unlock(self):
        created = self.handler.handle({
            "action": "create_vault",
            "master_password": "Master123!"
        })

        self.assertTrue(created["success"])

        unlocked = self.handler.handle({
            "action": "unlock_vault",
            "master_password": "Master123!"
        })

        self.assertTrue(unlocked["success"])

    # Ham ho tro: Them tai khoan mau de kiem thu.
    def add_sample_account(self):
        result = self.handler.handle({
            "action": "add_password",
            "website": "https://github.com",
            "username": "user123",
            "password": "Password123!",
            "note": "Test account"
        })

        self.assertTrue(result["success"])
        return result


if __name__ == "__main__":
    unittest.main()
