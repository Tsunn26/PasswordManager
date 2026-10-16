import os
import tempfile
import unittest

from modules import database as db
from modules import security


class IntegrationTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        db.set_db_path(
            os.path.join(self.tmp.name, "test.db")
        )
        db.init_db()

    def tearDown(self):
        db.set_db_path(db.DEFAULT_DB_PATH)
        self.tmp.cleanup()

    def test_full_workflow(self):
        # 1. Tao Vault
        self.assertTrue(
            security.create_vault("MasterPassword123!")
        )

        # 2. Mo Vault
        key = security.unlock_vault(
            "MasterPassword123!"
        )

        self.assertEqual(len(key), 32)

        # 3. Luu tai khoan
        account_id = security.save_password(
            "https://github.com",
            "user123",
            "password123",
            key,
            "Tai khoan GitHub"
        )

        # 4. Lay va giai ma
        accounts = security.get_passwords(key)

        self.assertEqual(len(accounts), 1)
        self.assertEqual(
            accounts[0]["username"], "user123"
        )
        self.assertEqual(
            accounts[0]["password"], "password123"
        )

        # 5. Cap nhat mat khau
        self.assertTrue(
            security.update_password(
                account_id,
                key,
                password="newpassword456"
            )
        )

        accounts = security.get_passwords(key)
        self.assertEqual(
            accounts[0]["password"],
            "newpassword456"
        )

        # 6. Xoa tai khoan
        self.assertTrue(
            security.delete_password(account_id)
        )

        self.assertEqual(
            security.get_passwords(key), []
        )

    def test_wrong_master_password(self):
        security.create_vault("CorrectPassword123!")

        with self.assertRaises(ValueError):
            security.unlock_vault("WrongPassword")


if __name__ == "__main__":
    unittest.main()