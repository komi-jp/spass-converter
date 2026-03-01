"""Tests for spass_converter.py"""

import base64
import csv
import io
import os

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.padding import PKCS7

# Ensure the project root is importable
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from spass_converter import (
    Credential,
    TableInfo,
    _decode_field,
    _normalize_url,
    decrypt_spass,
    export_1password,
    export_bitwarden,
    export_dashlane,
    export_google,
    export_keepass,
    export_lastpass,
    parse_credentials,
)


# ============================================================
# Helpers
# ============================================================

def _encrypt_test_data(plaintext: str, password: str) -> bytes:
    """Create a .spass-compatible encrypted payload for testing."""
    salt = os.urandom(20)
    iv = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=70000,
    )
    key = kdf.derive(password.encode("utf-8"))

    padder = PKCS7(128).padder()
    padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return base64.b64encode(salt + iv + ciphertext)


def _b64(s: str) -> str:
    """Base64-encode a UTF-8 string."""
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


SAMPLE_DECRYPTED = (
    "next_table\n"
    f"title;origin_url;username_value;password_value;otp;credential_memo\n"
    f"{_b64('GitHub')};{_b64('https://github.com')};{_b64('user1')};{_b64('pass1')};&&&NULL&&&;&&&NULL&&&\n"
    f"{_b64('Gmail')};{_b64('android://abc@com.google.android.gm')};{_b64('user2')};{_b64('pass2')};{_b64('otpauth://totp/test')};{_b64('my note')}\n"
    "\n"
    "next_table\n"
    "card_name;card_number;expiry\n"
    f"{_b64('Visa')};{_b64('4111111111111111')};{_b64('12/30')}\n"
)


# ============================================================
# _decode_field
# ============================================================

class TestDecodeField:
    def test_base64_string(self):
        assert _decode_field(_b64("hello")) == "hello"

    def test_null_marker(self):
        assert _decode_field("&&&NULL&&&") == ""

    def test_empty_string(self):
        assert _decode_field("") == ""

    def test_non_base64_passthrough(self):
        assert _decode_field("hello world") == "hello world"

    def test_url_passthrough(self):
        assert _decode_field("https://example.com") == "https://example.com"


# ============================================================
# _normalize_url
# ============================================================

class TestNormalizeUrl:
    def test_empty(self):
        assert _normalize_url("") == ("", None)

    def test_normal_url(self):
        assert _normalize_url("https://github.com") == ("https://github.com", None)

    def test_android_com(self):
        url, original = _normalize_url("android://abc@com.example.app")
        assert url == "https://www.example.com"
        assert original == "android://abc@com.example.app"

    def test_android_org(self):
        url, _ = _normalize_url("android://abc@org.mozilla.firefox")
        assert url == "https://www.mozilla.org"

    def test_android_no_at(self):
        url, original = _normalize_url("android://something")
        assert url == ""
        assert original == "android://something"

    def test_android_unknown_tld(self):
        url, original = _normalize_url("android://abc@xyz.unknown.app")
        assert url == ""
        assert original is not None


# ============================================================
# TableInfo
# ============================================================

class TestTableInfo:
    def test_is_credential_table_true(self):
        t = TableInfo(headers=["title", "username_value", "password_value", "otp"])
        assert t.is_credential_table is True

    def test_is_credential_table_false(self):
        t = TableInfo(headers=["card_name", "card_number"])
        assert t.is_credential_table is False

    def test_missing_password(self):
        t = TableInfo(headers=["username_value", "title"])
        assert t.is_credential_table is False


# ============================================================
# parse_credentials
# ============================================================

class TestParseCredentials:
    def test_basic_parse(self):
        creds, tables = parse_credentials(SAMPLE_DECRYPTED)
        assert len(creds) == 2
        assert len(tables) == 2

    def test_credential_fields(self):
        creds, _ = parse_credentials(SAMPLE_DECRYPTED)
        assert creds[0].title == "GitHub"
        assert creds[0].url == "https://github.com"
        assert creds[0].username == "user1"
        assert creds[0].password == "pass1"
        assert creds[0].totp == ""
        assert creds[0].note == ""

    def test_android_url_normalized(self):
        creds, _ = parse_credentials(SAMPLE_DECRYPTED)
        assert creds[1].url == "https://www.google.com"
        assert "android://" in creds[1].note

    def test_totp_and_note(self):
        creds, _ = parse_credentials(SAMPLE_DECRYPTED)
        assert creds[1].totp == "otpauth://totp/test"
        assert "my note" in creds[1].note

    def test_non_credential_table_skipped(self):
        creds, tables = parse_credentials(SAMPLE_DECRYPTED)
        assert tables[0].is_credential_table is True
        assert tables[1].is_credential_table is False
        assert tables[1].row_count == 1

    def test_empty_input(self):
        creds, tables = parse_credentials("")
        assert creds == []
        assert tables == []


# ============================================================
# decrypt_spass
# ============================================================

class TestDecryptSpass:
    def test_roundtrip(self):
        plaintext = "next_table\ntitle;username_value;password_value\ntest;user;pass\n"
        password = "testpassword123"
        encrypted = _encrypt_test_data(plaintext, password)
        result = decrypt_spass(encrypted, password)
        assert result.decode("utf-8") == plaintext

    def test_wrong_password(self):
        encrypted = _encrypt_test_data("hello", "correct")
        with pytest.raises(ValueError, match="password"):
            decrypt_spass(encrypted, "wrong")

    def test_empty_ciphertext(self):
        # salt(20) + iv(16) + no ciphertext
        fake = base64.b64encode(b"\x00" * 36)
        with pytest.raises(ValueError, match="empty"):
            decrypt_spass(fake, "test")

    def test_invalid_length(self):
        # salt(20) + iv(16) + 15 bytes (not multiple of 16)
        fake = base64.b64encode(b"\x00" * 36 + b"\x01" * 15)
        with pytest.raises(ValueError, match="block size"):
            decrypt_spass(fake, "test")


# ============================================================
# Export functions
# ============================================================

SAMPLE_CREDS = [
    Credential(
        title="Example",
        url="https://example.com",
        username="user",
        password="pass",
        totp="otpauth://totp/test",
        note="a note",
    ),
    Credential(
        title="Empty",
        url="",
        username="user2",
        password="pass2",
        totp="",
        note="",
    ),
]


def _parse_csv(text: str) -> list[list[str]]:
    return list(csv.reader(io.StringIO(text)))


class TestExportGoogle:
    def test_header(self):
        rows = _parse_csv(export_google(SAMPLE_CREDS))
        assert rows[0] == ["name", "url", "username", "password", "note"]

    def test_row_count(self):
        rows = _parse_csv(export_google(SAMPLE_CREDS))
        assert len(rows) == 3  # header + 2 data rows

    def test_fields(self):
        rows = _parse_csv(export_google(SAMPLE_CREDS))
        assert rows[1][0] == "Example"
        assert rows[1][2] == "user"


class TestExportBitwarden:
    def test_header(self):
        rows = _parse_csv(export_bitwarden(SAMPLE_CREDS))
        assert rows[0][0] == "folder"
        assert rows[0][-1] == "login_totp"

    def test_row_count(self):
        rows = _parse_csv(export_bitwarden(SAMPLE_CREDS))
        assert len(rows) == 3

    def test_type_field(self):
        rows = _parse_csv(export_bitwarden(SAMPLE_CREDS))
        assert rows[1][2] == "1"  # type = login


class TestExport1Password:
    def test_no_header(self):
        rows = _parse_csv(export_1password(SAMPLE_CREDS))
        assert len(rows) == 2  # no header, just 2 data rows
        assert rows[0][0] == "Example"


class TestExportLastPass:
    def test_header(self):
        rows = _parse_csv(export_lastpass(SAMPLE_CREDS))
        assert rows[0] == ["url", "username", "password", "totp", "extra", "name", "grouping", "fav"]

    def test_row_count(self):
        rows = _parse_csv(export_lastpass(SAMPLE_CREDS))
        assert len(rows) == 3


class TestExportKeePass:
    def test_header(self):
        rows = _parse_csv(export_keepass(SAMPLE_CREDS))
        assert rows[0] == ["Account", "Login Name", "Password", "Web Site", "Comments"]

    def test_totp_in_comments(self):
        rows = _parse_csv(export_keepass(SAMPLE_CREDS))
        assert "TOTP:" in rows[1][4]
        assert "otpauth://totp/test" in rows[1][4]


class TestExportDashlane:
    def test_header(self):
        rows = _parse_csv(export_dashlane(SAMPLE_CREDS))
        assert rows[0][0] == "username"
        assert rows[0][-1] == "otpSecret"

    def test_row_count(self):
        rows = _parse_csv(export_dashlane(SAMPLE_CREDS))
        assert len(rows) == 3
