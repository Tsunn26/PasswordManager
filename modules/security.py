
"""Module Security cho Password Manager.

Phụ trách:
- Tạo và mở vault bằng Master Password.
- Dẫn xuất khóa bằng PBKDF2-HMAC-SHA256.
- Mã hóa/giải mã thông tin tài khoản bằng AES-GCM.
- Gọi modules.database để lưu và đọc dữ liệu.
"""

import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from modules import database as db


KDF_NAME = "PBKDF2-HMAC-SHA256"
ITERATIONS = 600_000
KEY_LENGTH = 32
SALT_LENGTH = 16
NONCE_LENGTH = 12

VERIFICATION_TEXT = b"password-vault-verification"


def derive_key(master_password, salt, iterations=ITERATIONS):
    """Dẫn xuất khóa 32 byte từ Master Password."""
    if not isinstance(master_password, str) or not master_password:
        raise ValueError("Master Password không được để trong.")

    if not isinstance(salt, bytes) or len(salt) < 16:
        raise ValueError("Salt không hợp lệ.")

    if not isinstance(iterations, int) or iterations < 1:
        raise ValueError("Số vòng lặp PBKDF2 không hợp lệ.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=iterations,
    )

    return kdf.derive(master_password.encode("utf-8"))


def create_vault(master_password):
    """Tạo vault và lưu metadata xác minh Master Password."""
    db.init_db()

    if db.vault_exists():
        raise ValueError("Vault đã tồn tại.")

    salt = os.urandom(SALT_LENGTH)
    key = derive_key(master_password, salt)

    nonce = os.urandom(NONCE_LENGTH)
    encrypted_verifier = AESGCM(key).encrypt(
        nonce,
        VERIFICATION_TEXT,
        None,
    )

    # Ghép nonce và ciphertext thành một trường bytes.
    verification_data = nonce + encrypted_verifier

    kdf_params = json.dumps({
        "iterations": ITERATIONS,
        "length": KEY_LENGTH,
        "salt_length": SALT_LENGTH,
    })

    db.save_vault_metadata(
        kdf_name=KDF_NAME,
        kdf_salt=salt,
        kdf_params=kdf_params,
        verification_data=verification_data,
    )

    return True


def unlock_vault(master_password):
    """Xác minh Master Password; trả về khóa nếu đúng."""
    db.init_db()
    metadata = db.get_vault_metadata()

    if metadata is None:
        raise ValueError("Vault chưa được tạo.")

    if metadata["kdf_name"] != KDF_NAME:
        raise ValueError("KDF trong database không được hỗ trợ.")

    try:
        params = json.loads(metadata["kdf_params"])
        iterations = int(params["iterations"])

        if iterations < 1:
            raise ValueError("Tham số KDF không hợp lệ.")

        key = derive_key(
            master_password,
            metadata["kdf_salt"],
            iterations,
        )

        verification_data = bytes(metadata["verification_data"])

        if len(verification_data) <= NONCE_LENGTH:
            raise ValueError("Dữ liệu xác minh không hợp lệ.")

        nonce = verification_data[:NONCE_LENGTH]
        ciphertext = verification_data[NONCE_LENGTH:]

        plaintext = AESGCM(key).decrypt(
            nonce,
            ciphertext,
            None,
        )

        if plaintext != VERIFICATION_TEXT:
            raise ValueError("Master Password không đúng.")

        return key

    except (InvalidTag, KeyError, TypeError, json.JSONDecodeError):
        raise ValueError(
            "Master Password không đúng hoặc metadata bị lỗi."
        ) from None


def encrypt_password(password, key):
    """Mã hóa chuỗi bằng AES-GCM; trả về encrypted_data và nonce."""
    if not isinstance(password, str):
        raise TypeError("Dữ liệu cần mã hóa phải là chuỗi.")

    nonce = os.urandom(NONCE_LENGTH)

    encrypted_data = AESGCM(key).encrypt(
        nonce,
        password.encode("utf-8"),
        None,
    )

    return encrypted_data, nonce


def decrypt_password(encrypted_data, nonce, key):
    """Giải mã dữ liệu AES-GCM."""
    try:
        plaintext = AESGCM(key).decrypt(
            bytes(nonce),
            bytes(encrypted_data),
            None,
        )
        return plaintext.decode("utf-8")

    except (InvalidTag, UnicodeDecodeError, ValueError, TypeError):
        raise ValueError(
            "Không thể giải mã: khóa hoặc dữ liệu không hợp lệ."
        ) from None


def save_password(website, username, password, key, note=""):
    """Mã hóa username/password/note rồi lưu qua database."""
    payload = json.dumps(
        {
            "username": username,
            "password": password,
            "note": note,
        },
        ensure_ascii=False,
    )

    encrypted_data, nonce = encrypt_password(payload, key)

    return db.add_account(
        website,
        encrypted_data,
        nonce,
    )

def find_duplicate(website, username, key):
    """Tìm tài khoản đã lưu trùng website + username.

    database.py chỉ lọc theo website (username đang được mã hóa), sau đó hàm này giải
    mã từng bản ghi cùng website để so sánh username (bỏ khoảng trắng, không phân
    biệt hoa thường). Trả về id của tài khoản trùng đầu tiên, hoặc None.
    """
    wanted = username.strip().casefold()

    for account in db.find_accounts_by_url(website):
        payload = json.loads(
            decrypt_password(account["encrypted_data"], account["nonce"], key)
        )

        if payload.get("username", "").strip().casefold() == wanted:
            return account["id"]

    return None


"""
def get_passwords(key):
    #Lấy và giải mã danh sách tài khoản.
    results = []

    for item in db.get_accounts():
        account = db.get_account(item["id"])

        if account is None:
            continue

        plaintext = decrypt_password(
            account["encrypted_data"],
            account["nonce"],
            key,
        )

        payload = json.loads(plaintext)

        results.append({
            "id": account["id"],
            "website": account["url"],
            "username": payload["username"],
            "password": payload["password"],
            "note": payload.get("note", ""),
            "created_at": account["created_at"],
            "updated_at": account["updated_at"],
        })

    return results
"""

def update_password(
    account_id,
    key,
    website=None,
    username=None,
    password=None,
    note=None,
):
    #Cập nhật tài khoản; giữ nguyên trường nhạy cảm không được chỉ định.#
    account = db.get_account(account_id)

    if account is None:
        return False

    plaintext = decrypt_password(
        account["encrypted_data"],
        account["nonce"],
        key,
    )
    payload = json.loads(plaintext)

    if username is not None:
        payload["username"] = username

    if password is not None:
        payload["password"] = password

    if note is not None:
        payload["note"] = note

    encrypted_data, nonce = encrypt_password(
        json.dumps(payload, ensure_ascii=False),
        key,
    )

    if website is None:
        return db.update_account(
            account_id,
            encrypted_data,
            nonce,
        )

    return db.update_account(
        account_id,
        encrypted_data,
        nonce,
        url=website,
    )


def delete_password(account_id):
    #Xóa tài khoản qua database.
    return db.delete_account(account_id)

# thêm hàm xem mật khẩu
def get_password(account_id, key):
    """Lấy mật khẩu của một tài khoản theo ID."""
    account = db.get_account(account_id)

    if account is None:
        raise ValueError("Không tìm thấy tài khoản.")

    plaintext = decrypt_password(
        account["encrypted_data"],
        account["nonce"],
        key,
    )

    payload = json.loads(plaintext)
    return payload["password"]