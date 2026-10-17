
"""Module Main - Ket noi Browser Extension voi Password Manager.

Nhiem vu:
- Nhan thong diep JSON tu Chrome Native Messaging.
- Goi handler.py de xu ly yeu cau.
- Gui phan hoi JSON tro lai Browser Extension.

Giao thuc Native Messaging:
4 byte do dai (little-endian) + noi dung JSON UTF-8.
"""

import json
import struct
import sys
import traceback

from modules.handler import PasswordHandler


# Doc chinh xac so byte yeu cau tu luong dau vao.
# Tra ve None neu luong da ket thuc truoc khi doc du.
def read_exact(stream, size):
    data = bytearray()

    while len(data) < size:
        chunk = stream.read(size - len(data))

        if not chunk:
            return None

        data.extend(chunk)

    return bytes(data)


# Doc mot thong diep theo giao thuc Chrome Native Messaging.
# Doc 4 byte do dai, sau do doc va giai ma JSON.
def read_message(stream=None):
    if stream is None:
        stream = sys.stdin.buffer

    length_bytes = read_exact(stream, 4)

    if length_bytes is None:
        return None

    message_length = struct.unpack("<I", length_bytes)[0]

    # Gioi han 1 MB cho request de tranh du lieu qua lon.
    if message_length == 0 or message_length > 1024 * 1024:
        raise ValueError("Kích thước thông điệp không hợp lệ.")

    message_bytes = read_exact(stream, message_length)

    if message_bytes is None:
        raise ValueError("Thông điệp bị thiếu dữ liệu.")

    return json.loads(message_bytes.decode("utf-8"))


# Gui mot dictionary thanh thong diep Native Messaging.
# Ma hoa JSON thanh UTF-8 va them 4 byte do dai vao dau.
def send_message(response, stream=None):
    if stream is None:
        stream = sys.stdout.buffer

    message = json.dumps(
        response,
        ensure_ascii=False
    ).encode("utf-8")

    if len(message) > 1024 * 1024:
        raise ValueError("Phản hồi vượt quá kích thước cho phép.")

    stream.write(struct.pack("<I", len(message)))
    stream.write(message)
    stream.flush()


# Vong lap chinh cua Native Host.
# Nhan request, goi Handler va tra response.
def main():
    handler = PasswordHandler()

    while True:
        try:
            request = read_message()

            # Chrome dong ket noi thi dung chuong trinh.
            if request is None:
                break

            response = handler.handle(request)

        except (ValueError, TypeError, UnicodeError,
                json.JSONDecodeError) as exc:
            response = {
                "success": False,
                "error": str(exc)
            }

        except Exception:
            # Khong gui chi tiet loi noi bo cho Extension.
            # stderr dung de ghi loi, stdout chi danh cho JSON.
            traceback.print_exc(file=sys.stderr)

            response = {
                "success": False,
                "error": "Lỗi hệ thống."
            }

        send_message(response)


# Chi khoi chay vong lap khi chay truc tiep main.py.
# Khi import de test, main() se khong tu dong chay.

if __name__ == "__main__":
    # Dam bao stdin/stdout o che do binary tren Windows.
    if sys.platform == "win32":
        import msvcrt
        import os

        msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)

    main()
