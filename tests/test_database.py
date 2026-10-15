"""Kiểm thử modules/database.py (người 1). Chạy: python -m unittest discover -s tests"""
import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules import database as db  # noqa: E402


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        db.set_db_path(os.path.join(self.tmp.name, "sub", "test.db"))
        db.init_db()

    def tearDown(self):
        db.set_db_path(db.DEFAULT_DB_PATH)
        self.tmp.cleanup()

    def test_init_creates_file_and_is_idempotent(self):
        self.assertTrue(os.path.exists(db.get_db_path()))
        db.init_db()

    def test_add_and_get(self):
        a = db.add_account("https://example.com", b"cipher1", b"n" * 12)
        b = db.add_account("https://github.com", b"cipher2", b"m" * 12)
        self.assertEqual((a, b), (1, 2))
        accounts = db.get_accounts()
        self.assertEqual([x["url"] for x in accounts],
                         ["https://github.com", "https://example.com"])
        for acc in accounts:
            self.assertNotIn("encrypted_data", acc)
            self.assertNotIn("nonce", acc)

    def test_get_account_full_record(self):
        i = db.add_account("https://example.com", b"cipher", b"n" * 12)
        rec = db.get_account(i)
        self.assertEqual(rec["encrypted_data"], b"cipher")
        self.assertEqual(rec["nonce"], b"n" * 12)
        self.assertIsNone(db.get_account(999))

    def test_search(self):
        db.add_account("https://Example.com/login", b"c", b"n")
        db.add_account("https://github.com", b"c", b"n")
        self.assertEqual(len(db.search_account("example")), 1)
        self.assertEqual(len(db.search_account("  GITHUB ")), 1)
        self.assertEqual(db.search_account("nope"), [])
        self.assertEqual(db.search_account(""), [])

    def test_search_wildcards_are_literal(self):
        db.add_account("https://a.com", b"c", b"n")
        self.assertEqual(db.search_account("%"), [])
        self.assertEqual(db.search_account("_"), [])

    def test_sql_injection_is_inert(self):
        db.add_account("https://a.com", b"c", b"n")
        self.assertEqual(db.search_account("' OR '1'='1"), [])
        db.add_account("x'); DROP TABLE password_entries;--", b"c", b"n")
        self.assertEqual(len(db.get_accounts()), 2)

    def test_delete(self):
        i = db.add_account("https://a.com", b"c", b"n")
        self.assertTrue(db.delete_account(i))
        self.assertFalse(db.delete_account(i))
        self.assertEqual(db.get_accounts(), [])

    def test_update(self):
        i = db.add_account("https://a.com", b"old", b"n1")
        self.assertTrue(db.update_account(i, b"new", b"n2"))
        rec = db.get_account(i)
        self.assertEqual((rec["encrypted_data"], rec["nonce"], rec["url"]),
                         (b"new", b"n2", "https://a.com"))
        self.assertTrue(db.update_account(i, b"new2", b"n3", url="https://b.com"))
        self.assertEqual(db.get_account(i)["url"], "https://b.com")
        self.assertFalse(db.update_account(999, b"x", b"y"))

    def test_invalid_input_rejected(self):
        for args in [("", b"c", b"n"), (None, b"c", b"n"),
                     ("https://a.com", "text", b"n"),
                     ("https://a.com", b"", b"n"),
                     ("https://a.com", b"c", None),
                     ("h" * (db.MAX_URL_LENGTH + 1), b"c", b"n")]:
            with self.assertRaises(ValueError):
                db.add_account(*args)
        for bad in (0, -1, "1", None, True):
            with self.assertRaises(ValueError):
                db.delete_account(bad)
        self.assertEqual(db.get_accounts(), [])

    def test_vault_metadata(self):
        self.assertFalse(db.vault_exists())
        self.assertIsNone(db.get_vault_metadata())
        db.save_vault_metadata("scrypt", b"s" * 16, '{"n": 16384}', b"verify")
        self.assertTrue(db.vault_exists())
        meta = db.get_vault_metadata()
        self.assertEqual(meta["kdf_name"], "scrypt")
        self.assertEqual(meta["kdf_salt"], b"s" * 16)
        self.assertEqual(meta["verification_data"], b"verify")
        with self.assertRaises(db.DatabaseError):
            db.save_vault_metadata("scrypt", b"x", "{}", b"y")
        self.assertEqual(db.get_vault_metadata()["kdf_salt"], b"s" * 16)

    def test_schema_matches_plan(self):
        conn = sqlite3.connect(db.get_db_path())
        cols = lambda t: [r[1] for r in conn.execute(f"PRAGMA table_info({t})")]
        self.assertEqual(cols("vault_metadata"),
                         ["id", "kdf_name", "kdf_salt", "kdf_params", "verification_data"])
        self.assertEqual(cols("password_entries"),
                         ["id", "url", "encrypted_data", "nonce", "created_at", "updated_at"])
        conn.close()


if __name__ == "__main__":
    unittest.main()
