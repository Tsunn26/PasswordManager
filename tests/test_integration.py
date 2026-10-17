
"""Kiem thu tich hop Database - Security - Handler."""

import os
import tempfile
import unittest

from modules import database as db
from modules.handler import PasswordHandler


class IntegrationTests(unittest.TestCase):

    MASTER = "MasterPassword123!"

    def setUp(self):
        # Tao Database tam, khong anh huong Vault that.
        self.tmp = tempfile.TemporaryDirectory()

        db.set_db_path(
            os.path.join(self.tmp.name, "test.db")
        )

        self.handler = PasswordHandler()

    def tearDown(self):
        # Khoa Vault va khoi phuc duong dan Database.
        self.handler.lock_vault()
        db.set_db_path(db.DEFAULT_DB_PATH)
        self.tmp.cleanup()

    def request(self, action, **kwargs):
        return self.handler.handle({
            "action": action,
            **kwargs
        })

    def test_full_workflow(self):
        # 1. Tao Vault.
        result = self.request(
            "create_vault",
            master_password=self.MASTER
        )
        self.assertTrue(result["success"], result)

        # 2. Mo khoa Vault.
        result = self.request(
            "unlock_vault",
            master_password=self.MASTER
        )
        self.assertTrue(result["success"], result)

        # 3. Them tai khoan.
        result = self.request(
            "add_password",
            website="https://github.com",
            username="user123",
            password="password123",
            note="Tai khoan GitHub"
        )
        self.assertTrue(result["success"], result)

        account_id = result["id"]

        # 4. Kiem tra danh sach.
        result = self.request("get_passwords")

        self.assertTrue(result["success"], result)
        self.assertEqual(len(result["accounts"]), 1)

        account = result["accounts"][0]

        self.assertEqual(
            account["website"],
            "https://github.com"
        )
        self.assertEqual(
            account["username"],
            "user123"
        )

        # Danh sach khong duoc tra ve mat khau.
        self.assertNotIn("password", account)

        # 5. Xem mat khau bang Master Password.
        result = self.request(
            "reveal_password",
            id=account_id,
            master_password=self.MASTER
        )

        self.assertTrue(result["success"], result)
        self.assertEqual(
            result["password"],
            "password123"
        )

        # 6. Xac minh sai phai bi tu choi.
        result = self.request(
            "reveal_password",
            id=account_id,
            master_password="WrongPassword"
        )

        self.assertFalse(result["success"])

        # 7. Tim kiem tai khoan.
        result = self.request(
            "search_password",
            keyword="github"
        )

        self.assertTrue(result["success"], result)
        self.assertEqual(len(result["accounts"]), 1)
        self.assertNotIn(
            "password",
            result["accounts"][0]
        )

        # 8. Xoa tai khoan.
        result = self.request(
            "delete_password",
            id=account_id
        )

        self.assertTrue(result["success"], result)

        # 9. Kiem tra danh sach sau khi xoa.
        result = self.request("get_passwords")

        self.assertTrue(result["success"], result)
        self.assertEqual(result["accounts"], [])

        # 10. Khoa Vault.
        result = self.request("lock_vault")
        self.assertTrue(result["success"], result)

        # Khong duoc lay danh sach khi Vault da khoa.
        result = self.request("get_passwords")
        self.assertFalse(result["success"])

    def test_wrong_master_password(self):
        self.request(
            "create_vault",
            master_password=self.MASTER
        )

        result = self.request(
            "unlock_vault",
            master_password="WrongPassword"
        )

        self.assertFalse(result["success"])
        self.assertIsNone(self.handler.key)


if __name__ == "__main__":
    unittest.main()
