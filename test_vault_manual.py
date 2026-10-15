
import os
import tempfile

from cryptography.fernet import Fernet
from backend.vault import (
    create_vault,
    unlock_vault,
    encrypt_password,
    decrypt_password,
)


def main():
    with tempfile.TemporaryDirectory() as folder:
        db_path = os.path.join(folder, "test_vault.db")
        master = "Demo-Master-Password-2026!"

        # 1. Tạo kho
        assert create_vault(master, db_path) is True
        print("1. Tao vault: OK")

        # 2. Mở khóa bằng mật khẩu đúng
        key = unlock_vault(master, db_path)
        print("2. Mo khoa dung mat khau: OK")

        # 3. Mật khẩu Master sai phải bị từ chối
        try:
            unlock_vault("Sai-Master-Password", db_path)
        except ValueError:
            print("3. Tu choi Master Password sai: OK")
        else:
            raise AssertionError("Master Password sai van mo duoc vault")

        # 4. Mã hóa và giải mã phải trả lại đúng mật khẩu
        original = "Website-Password-123!"
        encrypted = encrypt_password(original, key)
        decrypted = decrypt_password(encrypted, key)

        assert decrypted == original
        assert encrypted != original.encode("utf-8")
        print("4. Ma hoa va giai ma: OK")

        # 5. Khóa sai phải không giải mã được
        wrong_key = Fernet.generate_key()

        try:
            decrypt_password(encrypted, wrong_key)
        except ValueError:
            print("5. Tu choi khoa sai: OK")
        else:
            raise AssertionError("Khoa sai van giai ma duoc")


if __name__ == "__main__":
    main()
