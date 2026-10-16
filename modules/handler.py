
"""Module Handler - Xu ly yeu cau cua Password Manager.

Nhiem vu:
- Nhan va phan loai yeu cau tu Browser Extension.
- Goi security.py de quan ly Vault va ma hoa du lieu.
- Goi database.py de tim kiem tai khoan.
- Quan ly trang thai khoa/mo Vault.
- Tra ket qua xu ly duoi dang dictionary.
"""

from modules import database as db
from modules import security


class PasswordHandler:

    # Khoi tao Handler va ket noi co so du lieu.
    # Ban dau Vault o trang thai khoa (self.key = None).
    def __init__(self):
        self.key = None
        db.init_db()

    # Ham trung tam: nhan request dang dictionary.
    # Dua vao action de chuyen yeu cau den ham xu ly tuong ung.
    # Ket qua tra ve co dang {"success": True/False, ...}.
    def handle(self, request):
        if not isinstance(request, dict):
            return {
                "success": False,
                "error": "Yeu cau khong hop le."
            }

        action = request.get("action")

        try:
            if action == "create_vault":
                return self.create_vault(request)

            elif action == "unlock_vault":
                return self.unlock_vault(request)

            elif action == "lock_vault":
                return self.lock_vault()

            elif action == "add_password":
                return self.add_password(request)

            elif action == "get_passwords":
                return self.get_passwords()

            elif action == "update_password":
                return self.update_password(request)

            elif action == "delete_password":
                return self.delete_password(request)

            elif action == "search_password":
                return self.search_password(request)

            else:
                return {
                    "success": False,
                    "error": "Action khong duoc ho tro."
                }

        except (ValueError, TypeError, db.DatabaseError) as exc:
            return {
                "success": False,
                "error": str(exc)
            }

    # Kiem tra Vault da duoc mo khoa hay chua.
    # Neu chua co khoa AES thi khong cho phep thao tac voi tai khoan.
    def _require_unlock(self):
        if self.key is None:
            raise ValueError("Vault dang khoa.")

    # Tao Vault moi bang Master Password.
    # Goi security.py de sinh salt, dan xuat khoa va luu metadata.
    def create_vault(self, request):
        password = request.get("master_password")

        if not isinstance(password, str) or not password:
            raise ValueError("Master Password khong hop le.")

        security.create_vault(password)

        return {
            "success": True
        }

    # Mo khoa Vault bang Master Password.
    # Neu xac minh thanh cong, luu khoa AES vao self.key.
    def unlock_vault(self, request):
        password = request.get("master_password")

        if not isinstance(password, str) or not password:
            raise ValueError("Master Password khong hop le.")

        key = security.unlock_vault(password)
        self.key = key

        return {
            "success": True
        }

    # Khoa Vault bang cach xoa tham chieu den khoa AES.
    # Sau khi khoa, cac thao tac voi tai khoan se bi tu choi.
    def lock_vault(self):
        self.key = None

        return {
            "success": True
        }

    # Them tai khoan moi vao Vault.
    # security.py ma hoa username, password va note truoc khi luu.
    def add_password(self, request):
        self._require_unlock()

        website = request.get("website")
        username = request.get("username")
        password = request.get("password")
        note = request.get("note", "")

        if not isinstance(website, str) or not website.strip():
            raise ValueError("Website khong hop le.")

        if not isinstance(username, str):
            raise ValueError("Username khong hop le.")

        if not isinstance(password, str):
            raise ValueError("Password khong hop le.")

        if not isinstance(note, str):
            raise ValueError("Note khong hop le.")

        account_id = security.save_password(
            website,
            username,
            password,
            self.key,
            note
        )

        return {
            "success": True,
            "id": account_id
        }

    # Lay danh sach tai khoan da luu trong Vault.
    # security.py doc du lieu tu database va giai ma bang khoa AES.
    def get_passwords(self):
        self._require_unlock()

        accounts = security.get_passwords(self.key)

        return {
            "success": True,
            "accounts": accounts
        }

    # Cap nhat thong tin tai khoan theo ID.
    # Chi thay doi cac truong duoc cung cap trong request.
    # Du lieu nhay cam se duoc ma hoa lai truoc khi luu.
    def update_password(self, request):
        self._require_unlock()

        account_id = request.get("id")

        if isinstance(account_id, bool) or not isinstance(account_id, int) or account_id <= 0:
            raise ValueError("ID tai khoan khong hop le.")

        website = request.get("website")
        username = request.get("username")
        password = request.get("password")
        note = request.get("note")

        if website is not None:
            if not isinstance(website, str) or not website.strip():
                raise ValueError("Website khong hop le.")

        for field, value in (
            ("Username", username),
            ("Password", password),
            ("Note", note)
        ):
            if value is not None and not isinstance(value, str):
                raise ValueError(f"{field} khong hop le.")

        updated = security.update_password(
            account_id,
            self.key,
            website=website,
            username=username,
            password=password,
            note=note
        )

        return {
            "success": updated
        }

    # Xoa tai khoan theo ID.
    # Chi cho phep xoa khi Vault da duoc mo khoa.
    def delete_password(self, request):
        self._require_unlock()

        account_id = request.get("id")

        if isinstance(account_id, bool) or not isinstance(account_id, int) or account_id <= 0:
            raise ValueError("ID tai khoan khong hop le.")

        deleted = security.delete_password(account_id)

        return {
            "success": deleted
        }

    # Tim kiem tai khoan theo website.
    # database.py tim ID phu hop, security.py giai ma du lieu.
    # Chi tra ve cac tai khoan trung voi ket qua tim kiem.
    def search_password(self, request):
        self._require_unlock()

        keyword = request.get("keyword")

        if not isinstance(keyword, str):
            raise ValueError("Tu khoa tim kiem khong hop le.")

        matches = db.search_account(keyword)
        matched_ids = {item["id"] for item in matches}

        accounts = [
            account
            for account in security.get_passwords(self.key)
            if account["id"] in matched_ids
        ]

        return {
            "success": True,
            "accounts": accounts
        }
