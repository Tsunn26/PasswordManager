
# create_vault()	    Tạo kho mật khẩu, sinh salt ngẫu nhiên, dẫn xuất khóa và lưu thông tin xác thực.
# unlock_vault()	    Nhận Master Password, kiểm tra đúng/sai và trả về khóa nếu đúng.
# encrypt_password()	Mã hóa mật khẩu website bằng Fernet trước khi lưu.
# decrypt_password()	Giải mã mật khẩu bằng khóa hợp lệ khi người dùng cần xem lại. 


import os
import sqlite3
import base64

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


DB_PATH = "vault.db"
ITERATIONS = 600_000


def get_connection(db_path=DB_PATH):
    """Tạo kết nối SQLite và các bảng cần thiết."""
    conn = sqlite3.connect(db_path)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS vault_metadata (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            salt BLOB NOT NULL,
            verifier BLOB NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            website TEXT NOT NULL,
            username TEXT NOT NULL,
            encrypted_password BLOB NOT NULL
        )
    """)

    return conn


def derive_key(master_password, salt):
    """Dẫn xuất khóa Fernet từ Master Password và salt."""
    if not isinstance(master_password, str) or not master_password:
        raise ValueError("Master Password không được để trống.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )

    raw_key = kdf.derive(master_password.encode("utf-8"))
    return base64.urlsafe_b64encode(raw_key)

"""chỉ có 1 kho mật khẩu (vault), lưu nhiều tài khoản, mk của nhiều website khác nhau"""
def create_vault(master_password, db_path=DB_PATH):
    """Khởi tạo kho mật khẩu lần đầu."""
    conn = get_connection(db_path)

    try:
        existing = conn.execute(
            "SELECT id FROM vault_metadata WHERE id = 1"
        ).fetchone()

        if existing:
            raise ValueError("Kho mật khẩu đã tồn tại.")

        salt = os.urandom(16)
        key = derive_key(master_password, salt)

        verifier = Fernet(key).encrypt(
            b"password-vault-verification"
        )

        conn.execute(
            """
            INSERT INTO vault_metadata (id, salt, verifier)
            VALUES (1, ?, ?)
            """,
            (salt, verifier),
        )

        conn.commit()
        return True

    finally:
        conn.close()

"""mở kho bằng Master Password"""
def unlock_vault(master_password, db_path=DB_PATH):
    """Kiểm tra Master Password và trả về khóa nếu đúng."""
    conn = get_connection(db_path)

    try:
        row = conn.execute(
            "SELECT salt, verifier FROM vault_metadata WHERE id = 1"
        ).fetchone()

        if row is None:
            raise ValueError("Kho mật khẩu chưa được tạo.")

        salt, verifier = row
        key = derive_key(master_password, salt)

        try:
            result = Fernet(key).decrypt(verifier)
        except InvalidToken:
            raise ValueError("Master Password không đúng.") from None

        if result != b"password-vault-verification":
            raise ValueError("Master Password không đúng.")

        return key

    finally:
        conn.close()

"""mã hóa mật khẩu trước khi lưu."""
def encrypt_password(password, key):
    """Mã hóa mật khẩu website thành token Fernet."""
    if not isinstance(password, str):
        raise TypeError("Mật khẩu phải là chuỗi.")

    return Fernet(key).encrypt(password.encode("utf-8"))

"""giải mã mật khẩu khi cần xem lại."""
def decrypt_password(encrypted_password, key):
    """Giải mã token Fernet để lấy lại mật khẩu website."""
    try:
        decrypted = Fernet(key).decrypt(encrypted_password)
        return decrypted.decode("utf-8")
    except InvalidToken:
        raise ValueError(
            "Không thể giải mã: khóa sai hoặc dữ liệu bị thay đổi."
        ) from None

"""lưu thêm tài khoản vào kho hiện có"""
def save_password(website, username, password, key, db_path=DB_PATH):
    """Mã hóa rồi lưu thông tin tài khoản vào SQLite."""
    encrypted = encrypt_password(password, key)
    conn = get_connection(db_path)

    try:
        conn.execute(
            """
            INSERT INTO passwords
                (website, username, encrypted_password)
            VALUES (?, ?, ?)
            """,
            (website, username, encrypted),
        )
        conn.commit()
    finally:
        conn.close()


def get_passwords(key, db_path=DB_PATH):
    """Đọc tài khoản đã lưu và giải mã mật khẩu."""
    conn = get_connection(db_path)

    try:
        rows = conn.execute(
            """
            SELECT id, website, username, encrypted_password
            FROM passwords
            ORDER BY id
            """
        ).fetchall()

        return [
            {
                "id": row[0],
                "website": row[1],
                "username": row[2],
                "password": decrypt_password(row[3], key),
            }
            for row in rows
        ]
    finally:
        conn.close()
