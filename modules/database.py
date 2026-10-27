"""
database.py - NGƯỜI 1: Quản lý tài khoản và cơ sở dữ liệu SQLite.

Phạm vi của module:
    * Tạo/kết nối SQLite và tạo bảng (vault_metadata, password_entries).
    * Các hàm CRUD cho bảng password_entries:
        add_account(), get_accounts(), search_account(), delete_account()
        (+ get_account(), update_account() phục vụ get_password / cập nhật).
    * Lưu / đọc thông tin vault (salt, tham số KDF, verification_data).

Nguyên tắc (theo kế hoạch dự án):
    * database.py CHỈ truy vấn và lưu dữ liệu, KHÔNG tự mã hóa/giải mã.
      Phần nhạy cảm (username, password, note) do security.py (người 2) mã hóa
      thành `encrypted_data` + `nonce` rồi truyền vào đây dưới dạng bytes.
    * Mọi câu lệnh SQL đều dùng tham số hóa (?) để chống SQL Injection.
    * Không lưu Master Password / khóa dẫn xuất ở dạng bản rõ.
    * File passwords.db được tạo tự động khi chạy, không đẩy lên Git.

Ví dụ dùng:
    from modules import database as db
    db.init_db()
    new_id = db.add_account("https://example.com", encrypted_bytes, nonce_bytes)
    db.get_accounts()                       # danh sách (không có dữ liệu nhạy cảm)
    db.search_account("example")            # tìm theo website
    db.delete_account(new_id)
"""

import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator, Optional

# ---------------------------------------------------------------------------
# Cấu hình đường dẫn
# ---------------------------------------------------------------------------
_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_DB_PATH = os.path.join(_BASE_DIR, "data", "passwords.db")

# Đường dẫn đang dùng (có thể đổi bằng set_db_path(), ví dụ khi test).
_db_path = DEFAULT_DB_PATH

# Giới hạn độ dài URL để tránh dữ liệu bất thường (khớp bước validate của handler).
MAX_URL_LENGTH = 2048


class DatabaseError(Exception):
    """Lỗi chung của tầng cơ sở dữ liệu."""


# ---------------------------------------------------------------------------
# Kết nối & khởi tạo
# ---------------------------------------------------------------------------
def set_db_path(path: str) -> None:
    """Đổi đường dẫn file database (dùng cho kiểm thử). Truyền ':memory:' không được
    hỗ trợ vì mỗi kết nối sẽ tạo một DB trống riêng."""
    global _db_path
    _db_path = path


def get_db_path() -> str:
    return _db_path


def _now() -> str:
    """Thời điểm hiện tại theo UTC, định dạng ISO 8601."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def _connect() -> Iterator[sqlite3.Connection]:
    """Mở kết nối SQLite, tự commit khi thành công, rollback khi lỗi và luôn đóng."""
    directory = os.path.dirname(_db_path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    conn = sqlite3.connect(_db_path)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        yield conn
        conn.commit()
    except sqlite3.Error as exc:
        conn.rollback()
        raise DatabaseError(f"Lỗi cơ sở dữ liệu: {exc}") from exc
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    """Tạo file database và các bảng nếu chưa tồn tại (an toàn khi gọi nhiều lần)."""
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS vault_metadata (
                id                INTEGER PRIMARY KEY CHECK (id = 1),
                kdf_name          TEXT NOT NULL,
                kdf_salt          BLOB NOT NULL,
                kdf_params        TEXT NOT NULL,
                verification_data BLOB NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS password_entries (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                url            TEXT NOT NULL,
                encrypted_data BLOB NOT NULL,
                nonce          BLOB NOT NULL,
                created_at     TEXT NOT NULL,
                updated_at     TEXT NOT NULL
            )
            """
        ) ######################################## Cập nhật #############################################
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_password_entries_url "
            "ON password_entries (url)"
        )
        conn.execute(
        """
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until REAL NOT NULL DEFAULT 0
        )
        """
        )
        conn.execute(
        """
        INSERT OR IGNORE INTO login_attempts
        (id, failed_attempts, locked_until)
        VALUES (1, 0, 0)
        """
    )

# ---------------------------------------------------------------------------
# Kiểm tra đầu vào
# ---------------------------------------------------------------------------
def _check_url(url) -> str:
    if not isinstance(url, str) or not url.strip():
        raise ValueError("url phải là chuỗi không rỗng")
    url = url.strip()
    if len(url) > MAX_URL_LENGTH:
        raise ValueError("url quá dài")
    return url


def _check_blob(value, name: str) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise ValueError(f"{name} phải là bytes")
    value = bytes(value)
    if not value:
        raise ValueError(f"{name} không được rỗng")
    return value


def _check_id(account_id) -> int:
    # bool là subclass của int nên loại ra riêng.
    if isinstance(account_id, bool) or not isinstance(account_id, int) or account_id < 1:
        raise ValueError("account_id phải là số nguyên dương")
    return account_id


def _row_to_dict(row: sqlite3.Row) -> dict:
    return {key: row[key] for key in row.keys()}


# ---------------------------------------------------------------------------
# CRUD tài khoản (bảng password_entries)
# ---------------------------------------------------------------------------
def add_account(url: str, encrypted_data: bytes, nonce: bytes) -> int:
    """Thêm một tài khoản mới.

    Args:
        url: website liên kết với tài khoản.
        encrypted_data: bản mã (bytes) chứa username/password/note, do security.py tạo.
        nonce: nonce AES-GCM đi kèm bản mã.

    Returns:
        id của bản ghi vừa thêm.
    """
    url = _check_url(url)
    encrypted_data = _check_blob(encrypted_data, "encrypted_data")
    nonce = _check_blob(nonce, "nonce")
    now = _now()
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO password_entries "
            "(url, encrypted_data, nonce, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (url, encrypted_data, nonce, now, now),
        )
        return cur.lastrowid


def get_accounts() -> list:
    """Lấy danh sách tất cả tài khoản (mới nhất trước).

    Chỉ trả về thông tin KHÔNG nhạy cảm: id, url, created_at, updated_at.
    Bản mã không nằm trong danh sách; dùng get_account(id) khi cần giải mã.
    """
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, url, created_at, updated_at "
            "FROM password_entries ORDER BY id DESC"
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def search_account(keyword: str) -> list:
    """Tìm tài khoản theo website (so khớp một phần, không phân biệt hoa thường).

    Trả về cùng cấu trúc như get_accounts(). Keyword rỗng -> danh sách rỗng.
    Ký tự đặc biệt của LIKE (% _ \\) được escape nên được hiểu là ký tự thường.
    """
    if not isinstance(keyword, str):
        raise ValueError("keyword phải là chuỗi")
    keyword = keyword.strip()
    if not keyword:
        return []
    escaped = (
        keyword.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    )
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, url, created_at, updated_at FROM password_entries "
            "WHERE url LIKE ? ESCAPE '\\' COLLATE NOCASE ORDER BY id DESC",
            (f"%{escaped}%",),
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def get_account(account_id: int) -> Optional[dict]:
    """Lấy một bản ghi đầy đủ (gồm encrypted_data, nonce) theo id để giải mã.

    Trả về None nếu không tồn tại.
    """
    account_id = _check_id(account_id)
    with _connect() as conn:
        row = conn.execute(
            "SELECT id, url, encrypted_data, nonce, created_at, updated_at "
            "FROM password_entries WHERE id = ?",
            (account_id,),
        ).fetchone()
    return _row_to_dict(row) if row else None


def update_account(
    account_id: int,
    encrypted_data: bytes,
    nonce: bytes,
    url: Optional[str] = None,
) -> bool:
    """Thay thế bản mã (và tùy chọn url) của một tài khoản.

    Returns:
        True nếu cập nhật được, False nếu không có tài khoản với id đó.
    """
    account_id = _check_id(account_id)
    encrypted_data = _check_blob(encrypted_data, "encrypted_data")
    nonce = _check_blob(nonce, "nonce")
    now = _now()
    with _connect() as conn:
        if url is None:
            cur = conn.execute(
                "UPDATE password_entries "
                "SET encrypted_data = ?, nonce = ?, updated_at = ? WHERE id = ?",
                (encrypted_data, nonce, now, account_id),
            )
        else:
            url = _check_url(url)
            cur = conn.execute(
                "UPDATE password_entries "
                "SET url = ?, encrypted_data = ?, nonce = ?, updated_at = ? "
                "WHERE id = ?",
                (url, encrypted_data, nonce, now, account_id),
            )
        return cur.rowcount > 0


def delete_account(account_id: int) -> bool:
    """Xóa tài khoản theo id.

    Returns:
        True nếu đã xóa, False nếu không tồn tại.
    """
    account_id = _check_id(account_id)
    with _connect() as conn:
        cur = conn.execute(
            "DELETE FROM password_entries WHERE id = ?", (account_id,)
        )
        return cur.rowcount > 0


# ---------------------------------------------------------------------------
# Vault metadata (salt, tham số KDF, dữ liệu xác minh) - dùng cho security.py
# ---------------------------------------------------------------------------
def vault_exists() -> bool:
    """Đã có vault (đã tạo Master Password) hay chưa."""
    with _connect() as conn:
        row = conn.execute("SELECT 1 FROM vault_metadata WHERE id = 1").fetchone()
    return row is not None


def save_vault_metadata(
    kdf_name: str, kdf_salt: bytes, kdf_params: str, verification_data: bytes
) -> None:
    """Lưu thông tin vault lần đầu. Chỉ có một bản ghi (id = 1).

    Raises:
        DatabaseError: nếu vault đã tồn tại (tránh ghi đè salt làm mất dữ liệu cũ).
    """
    if not isinstance(kdf_name, str) or not kdf_name.strip():
        raise ValueError("kdf_name phải là chuỗi không rỗng")
    if not isinstance(kdf_params, str) or not kdf_params.strip():
        raise ValueError("kdf_params phải là chuỗi (ví dụ JSON)")
    kdf_salt = _check_blob(kdf_salt, "kdf_salt")
    verification_data = _check_blob(verification_data, "verification_data")
    with _connect() as conn:
        if conn.execute("SELECT 1 FROM vault_metadata WHERE id = 1").fetchone():
            raise DatabaseError("Vault đã tồn tại")
        conn.execute(
            "INSERT INTO vault_metadata "
            "(id, kdf_name, kdf_salt, kdf_params, verification_data) "
            "VALUES (1, ?, ?, ?, ?)",
            (kdf_name.strip(), kdf_salt, kdf_params, verification_data),
        )


def get_vault_metadata() -> Optional[dict]:
    """Đọc thông tin vault; None nếu chưa khởi tạo."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT id, kdf_name, kdf_salt, kdf_params, verification_data "
            "FROM vault_metadata WHERE id = 1"
        ).fetchone()
    return _row_to_dict(row) if row else None
################################ Cập nhật ###############################################
def get_login_attempts():
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT failed_attempts, locked_until
            FROM login_attempts
            WHERE id = 1
            """
        ).fetchone()

    return dict(row)


def update_login_attempts(failed_attempts, locked_until):
    with _connect() as conn:
        conn.execute(
            """
            UPDATE login_attempts
            SET failed_attempts = ?, locked_until = ?
            WHERE id = 1
            """,
            (failed_attempts, locked_until)
        )


def reset_login_attempts():
    update_login_attempts(0, 0)