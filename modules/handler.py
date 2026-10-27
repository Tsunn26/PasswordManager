"""Module Handler - Xử lý yêu cầu của Password Manager.

Nhiệm vụ:
- Nhận và phân loại yêu cầu từ Browser Extension.
- Gọi security.py để quản lý Vault và mã hóa dữ liệu.
- Gọi database.py để tìm kiếm tài khoản.
- Quản lý trạng thái khóa/mở Vault.
- Trả kết quả xử lý dưới dạng dictionary.
"""
import json
import hmac
from modules import database as db
from modules import security


class PasswordHandler:

    # Khởi tạo Handler và kết nối cơ sở dữ liệu.
    # Ban đầu Vault ở trạng thái khóa (self.key = None).
    def __init__(self):
        self.key = None
        db.init_db()

    # Hàm trung tâm: nhận request dạng dictionary.
    # Dựa vào action để chuyển yêu cầu đến hàm xử lý tương ứng.
    # Kết quả trả về có dạng {"success": True/False, ...}.
    def handle(self, request):
        if not isinstance(request, dict):
            return {
                "success": False,
                "error": "Yêu cầu không hợp lệ."
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

            elif action == "reveal_password":
                return self.reveal_password(request)

            elif action == "update_password":
                return self.update_password(request)

            elif action == "delete_password":
                return self.delete_password(request)

            elif action == "search_password":
                return self.search_password(request)

            else:
                return {
                    "success": False,
                    "error": "Action không được hỗ trợ."
                }

        except (ValueError, TypeError, db.DatabaseError) as exc:
            return {
                "success": False,
                "error": str(exc)
            }

    # Kiểm tra Vault đã được mở khóa hay chưa.
    # Nếu chưa có khóa AES thì không cho phép thao tác với tài khoản.
    def _require_unlock(self):
        if self.key is None:
            raise ValueError("Vault đang khóa.")

    # Tìm tài khoản trùng website + username.
    # Username nằm trong dữ liệu đã mã hóa nên phải giải mã để so sánh.
    # Trả về (id, cùng_password) nếu trùng, ngược lại trả về None.
    def _find_duplicate(self, website, username, password):
        target_url = website.strip().lower()

        for account in db.get_accounts():
            if account["url"].strip().lower() != target_url:
                continue

            full_account = db.get_account(account["id"])

            if full_account is None:
                continue

            plaintext = security.decrypt_password(
                full_account["encrypted_data"],
                full_account["nonce"],
                self.key
            )
            payload = json.loads(plaintext)

            if payload.get("username") == username:
                same_password = hmac.compare_digest(
                    payload.get("password", "").encode("utf-8"),
                    password.encode("utf-8")
                )
                return account["id"], same_password

        return None

    # Tạo Vault mới bằng Master Password.
    # Gọi security.py để sinh salt, dẫn xuất khóa và lưu metadata.
    def create_vault(self, request):
        password = request.get("master_password")

        if not isinstance(password, str) or not password:
            raise ValueError("Master Password không hợp lệ.")

        security.create_vault(password)

        return {
            "success": True
        }

    # Mở khóa Vault bằng Master Password.
    # Nếu xác minh thành công, lưu khóa AES vào self.key.
    def unlock_vault(self, request):
        password = request.get("master_password")

        if not isinstance(password, str) or not password:
            raise ValueError("Master Password không hợp lệ.")

        key = security.unlock_vault(password)
        self.key = key

        return {
            "success": True
        }

    # Khóa Vault bằng cách xóa tham chiếu đến khóa AES.
    # Sau khi khóa, các thao tác với tài khoản sẽ bị từ chối.
    def lock_vault(self):
        self.key = None

        return {
            "success": True
        }

    # Thêm tài khoản mới vào Vault.
    # security.py mã hóa username, password và note trước khi lưu.
    def add_password(self, request):
        self._require_unlock()

        website = request.get("website")
        username = request.get("username")
        password = request.get("password")
        note = request.get("note", "")

        if not isinstance(website, str) or not website.strip():
            raise ValueError("Website không hợp lệ.")

        if not isinstance(username, str):
            raise ValueError("Username không hợp lệ.")

        if not isinstance(password, str):
            raise ValueError("Password không hợp lệ.")

        if not isinstance(note, str):
            raise ValueError("Note không hợp lệ.")

        # Kiểm tra trùng url + username trước khi thêm.
        duplicate = self._find_duplicate(website, username, password)

        if duplicate is not None:
            existing_id, same_password = duplicate

            if same_password:
                # Trùng cả url, username và password: chỉ báo, không lưu.
                return {
                    "success": True,
                    "status": "duplicate_same_password",
                    "id": existing_id
                }

            # Trùng url + username nhưng khác password: để người dùng
            # quyết định có cập nhật hay không.
            return {
                "success": True,
                "status": "duplicate_diff_password",
                "id": existing_id
            }

        account_id = security.save_password(
            website,
            username,
            password,
            self.key,
            note
        )

        return {
            "success": True,
            "status": "added",
            "id": account_id
        }

    # Lấy danh sách tài khoản đã lưu trong Vault.
    # security.py đọc dữ liệu từ database và giải mã bằng khóa AES.
    def get_passwords(self):
        self._require_unlock()

        accounts = db.get_accounts()
        safe_accounts = []

        for account in accounts:
            full_account = db.get_account(account["id"])

            plaintext = security.decrypt_password(
                full_account["encrypted_data"],
                full_account["nonce"],
                self.key
            )

            payload = json.loads(plaintext)

            safe_accounts.append({
                "id": account["id"],
                "website": account["url"],
                "username": payload["username"],
                "note": payload.get("note", ""),
                "created_at": account["created_at"],
                "updated_at": account["updated_at"]
            })

        return {
            "success": True,
            "accounts": safe_accounts
        }

    # Cập nhật thông tin tài khoản theo ID.
    # Chỉ thay đổi các trường được cung cấp trong request.
    # Dữ liệu nhạy cảm sẽ được mã hóa lại trước khi lưu.
    def update_password(self, request):
        self._require_unlock()

        account_id = request.get("id")

        if isinstance(account_id, bool) or not isinstance(account_id, int) or account_id <= 0:
            raise ValueError("ID tài khoản không hợp lệ.")

        website = request.get("website")
        username = request.get("username")
        password = request.get("password")
        note = request.get("note")

        if website is not None:
            if not isinstance(website, str) or not website.strip():
                raise ValueError("Website không hợp lệ.")

        for field, value in (
            ("Username", username),
            ("Password", password),
            ("Note", note)
        ):
            if value is not None and not isinstance(value, str):
                raise ValueError(f"{field} không hợp lệ.")

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

    # Xóa tài khoản theo ID.
    # Chỉ cho phép xóa khi Vault đã được mở khóa.
    def delete_password(self, request):
        self._require_unlock()

        account_id = request.get("id")

        if isinstance(account_id, bool) or not isinstance(account_id, int) or account_id <= 0:
            raise ValueError("ID tài khoản không hợp lệ.")

        deleted = security.delete_password(account_id)

        return {
            "success": deleted
        }

    # Tìm kiếm tài khoản theo website.
    # database.py tìm ID phù hợp, security.py giải mã dữ liệu.
    # Chỉ trả về các tài khoản trùng với kết quả tìm kiếm.
    def search_password(self, request):
        self._require_unlock()

        keyword = request.get("keyword")

        if not isinstance(keyword, str):
            raise ValueError("Từ khóa tìm kiếm không hợp lệ.")

        matches = db.search_account(keyword)
        matched_ids = {item["id"] for item in matches}

        accounts = [
            account
            for account in self.get_passwords()["accounts"]
            if account["id"] in matched_ids
        ]

        return {
            "success": True,
            "accounts": accounts
        }

    # Xác minh lại Master Password trước khi xem mật khẩu.
    def reveal_password(self, request):
        self._require_unlock()

        account_id = request.get("id")
        master_password = request.get("master_password")

        if (
            isinstance(account_id, bool)
            or not isinstance(account_id, int)
            or account_id <= 0
        ):
            raise ValueError("ID tài khoản không hợp lệ.")

        if not isinstance(master_password, str) or not master_password:
            raise ValueError("Vui lòng nhập Master Password.")

        # Xác minh lại Master Password.
        key = security.unlock_vault(master_password)

        # Tìm tài khoản cần xem.
        account = db.get_account(account_id)

        if account is None:
            raise ValueError("Không tìm thấy tài khoản.")

        # Giải mã dùng tài khoản được yêu cầu.
        plaintext = security.decrypt_password(
            account["encrypted_data"],
            account["nonce"],
            key
        )

        payload = json.loads(plaintext)

        return {
            "success": True,
            "password": payload["password"]
        }