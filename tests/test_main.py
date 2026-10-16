
"""Kiem thu main.py - Chrome Native Messaging.

Chay:
python -m unittest discover -s tests -v
"""

import io
import json
import struct
import unittest

from main import read_exact, read_message, send_message
from modules.handler import PasswordHandler


class MainTests(unittest.TestCase):

    # Test 1: Doc chinh xac so byte yeu cau.
    def test_read_exact(self):
        stream = io.BytesIO(b"abcdef")

        result = read_exact(stream, 4)

        self.assertEqual(result, b"abcd")

    # Test 2: Doc thong diep JSON hop le.
    def test_read_message(self):
        request = {
            "action": "get_passwords"
        }

        data = json.dumps(request).encode("utf-8")
        packet = struct.pack("<I", len(data)) + data

        result = read_message(io.BytesIO(packet))

        self.assertEqual(result, request)

    # Test 3: Gui thong diep JSON dung dinh dang.
    def test_send_message(self):
        response = {
            "success": True
        }

        stream = io.BytesIO()

        send_message(response, stream)

        packet = stream.getvalue()

        message_length = struct.unpack(
            "<I", packet[:4]
        )[0]

        message_data = json.loads(
            packet[4:].decode("utf-8")
        )

        self.assertEqual(
            message_length,
            len(packet[4:])
        )

        self.assertEqual(message_data, response)

    # Test 4: Doc thong diep co ky tu tieng Viet.
    def test_unicode_message(self):
        request = {
            "action": "search_password",
            "keyword": "Tai khoan cua toi"
        }

        data = json.dumps(
            request,
            ensure_ascii=False
        ).encode("utf-8")

        packet = struct.pack("<I", len(data)) + data

        result = read_message(io.BytesIO(packet))

        self.assertEqual(result, request)

    # Test 5: Tu choi thong diep co kich thuoc bang 0.
    def test_invalid_message_length(self):
        packet = struct.pack("<I", 0)

        with self.assertRaises(ValueError):
            read_message(io.BytesIO(packet))

    # Test 6: Tu choi thong diep thieu du lieu.
    def test_incomplete_message(self):
        packet = struct.pack("<I", 10) + b"abc"

        with self.assertRaises(ValueError):
            read_message(io.BytesIO(packet))

    # Test 7: Doc ket thuc luong du lieu.
    def test_end_of_stream(self):
        result = read_message(io.BytesIO(b""))

        self.assertIsNone(result)

    # Test 8: Kiem tra Handler nhan action khong hop le.
    # Khong can tao Vault de kiem thu truong hop nay.
    def test_handler_invalid_action(self):
        # Tao doi tuong Handler nhung tranh khoi tao DB that.
        handler = PasswordHandler.__new__(PasswordHandler)
        handler.key = None

        result = handler.handle({
            "action": "unknown_action"
        })

        self.assertFalse(result["success"])


if __name__ == "__main__":
    unittest.main()
