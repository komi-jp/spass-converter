#!/usr/bin/env python3
"""
spass-converter: Samsung Pass Data Portability Tool

Converts Samsung Pass .spass export files into CSV formats compatible
with various password managers. Runs entirely offline on your local machine.

DISCLAIMER:
  This is an unofficial open-source tool intended solely for personal data migration.
  It is not affiliated with Samsung, Google, Bitwarden, or any other company.
  The developer assumes no responsibility for data loss or leakage.
  Please securely delete the generated CSV files after import.
"""

import argparse
import base64
import csv
import getpass
import io
import os
import sys
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.padding import PKCS7

DISCLAIMER = """\
========================================================
  spass-converter - Samsung Pass Data Portability Tool
========================================================
DISCLAIMER:
  This is an unofficial open-source tool for personal
  data migration only. Not affiliated with Samsung,
  Google, Bitwarden, or any other company.
  The developer assumes no responsibility for data loss
  or leakage. Please securely delete CSV files after
  importing into your password manager.
========================================================"""

# ============================================================
# Layer 1: Decryption
# ============================================================

SALT_LENGTH = 20
IV_LENGTH = 16
PBKDF2_ITERATIONS = 70000
KEY_LENGTH = 32  # AES-256


def decrypt_spass(encrypted_data: bytes, password: str) -> bytes:
    """
    Decrypt .spass encrypted data.

    Structure: Base64( salt[20] + IV[16] + ciphertext )
    Key derivation: PBKDF2-SHA256 (70,000 iterations)
    Cipher: AES-256-CBC + PKCS7 padding
    """
    decoded = base64.b64decode(encrypted_data)

    salt = decoded[:SALT_LENGTH]
    iv = decoded[SALT_LENGTH : SALT_LENGTH + IV_LENGTH]
    ciphertext = decoded[SALT_LENGTH + IV_LENGTH :]

    if len(ciphertext) == 0:
        raise ValueError("Ciphertext is empty. The file may be corrupted.")
    if len(ciphertext) % 16 != 0:
        raise ValueError("Invalid ciphertext length (not a multiple of AES block size).")

    # Key derivation
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    key = kdf.derive(password.encode("utf-8"))

    # AES-256-CBC decryption
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()

    # PKCS7 unpadding
    try:
        unpadder = PKCS7(128).unpadder()
        plaintext = unpadder.update(plaintext_padded) + unpadder.finalize()
    except ValueError:
        raise ValueError("Decryption failed. The password may be incorrect.")

    return plaintext


# ============================================================
# Layer 2: Data Mapping
# ============================================================

NULL_MARKER = "&&&NULL&&&"
_BASE64_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")


@dataclass
class Credential:
    """Intermediate data model for a login credential."""

    title: str = ""
    url: str = ""
    username: str = ""
    password: str = ""
    totp: str = ""
    note: str = ""


def _decode_field(value: str) -> str:
    """Decode a base64-encoded field and strip NULL markers."""
    if not value or value == NULL_MARKER:
        return ""
    try:
        # Heuristic: only attempt base64 decode if the value consists entirely
        # of valid base64 characters (filters out plaintext with spaces, @, etc.)
        if all(c in _BASE64_CHARS for c in value):
            return base64.b64decode(value).decode("utf-8")
    except Exception:
        pass
    return value


def _normalize_url(url: str) -> tuple[str, Optional[str]]:
    """
    Normalize a URL.

    For android:// scheme URLs, attempt to infer a web domain from
    the package name and return the original URL for the notes field.

    Returns:
        (normalized_url, original_url_for_note)
    """
    if not url:
        return ("", None)

    if not url.startswith("android://"):
        return (url, None)

    original = url
    # Extract package name from android://hash@com.example.app
    if "@" in url:
        package = url.split("@", 1)[1]
        parts = package.split(".")
        tld_prefixes = ("com", "org", "net", "io", "jp", "co", "me", "dev", "app")
        if len(parts) >= 2 and parts[0] in tld_prefixes:
            domain = parts[1] + "." + parts[0]
            return (f"https://www.{domain}", original)

    return ("", original)


@dataclass
class TableInfo:
    """Metadata about a detected table in the decrypted data."""

    headers: list[str]
    row_count: int = 0

    @property
    def is_credential_table(self) -> bool:
        return "username_value" in self.headers and "password_value" in self.headers


def parse_credentials(decrypted_text: str) -> tuple[list[Credential], list[TableInfo]]:
    """
    Parse credentials from decrypted .spass text.

    .spass data structure:
    - Tables are separated by "next_table" lines
    - First line after separator is semicolon-delimited headers
    - Subsequent lines are semicolon-delimited, base64-encoded fields

    Only tables containing both "username_value" and "password_value" headers
    are treated as credential tables. Other tables (cards, addresses, notes)
    are skipped.

    Returns:
        (credentials, all_tables): Parsed credentials and metadata for all tables
    """
    credentials: list[Credential] = []
    all_tables: list[TableInfo] = []
    lines = decrypted_text.splitlines()

    in_table = False
    headers: list[str] = []
    current_table: Optional[TableInfo] = None

    for line in lines:
        if line == "next_table":
            in_table = True
            headers = []
            current_table = None
            continue

        if in_table and not headers:
            headers = line.split(";")
            current_table = TableInfo(headers=headers)
            all_tables.append(current_table)
            continue

        if in_table and headers:
            if not line.strip():
                in_table = False
                continue

            fields = line.split(";")
            if len(fields) != len(headers):
                continue

            if current_table:
                current_table.row_count += 1

            if not current_table or not current_table.is_credential_table:
                continue

            row = dict(zip(headers, fields))

            # Decode and clean all fields in one pass
            decoded_row = {k: _decode_field(v) for k, v in row.items()}

            # Normalize URL
            normalized_url, original_url = _normalize_url(decoded_row.get("origin_url", ""))

            # Build note
            note_parts = []
            memo = decoded_row.get("credential_memo", "")
            if memo:
                note_parts.append(memo)
            if original_url:
                note_parts.append(f"Original URL: {original_url}")

            cred = Credential(
                title=decoded_row.get("title", ""),
                url=normalized_url,
                username=decoded_row.get("username_value", ""),
                password=decoded_row.get("password_value", ""),
                totp=decoded_row.get("otp", ""),
                note="\n".join(note_parts),
            )
            credentials.append(cred)

    return credentials, all_tables


# ============================================================
# Layer 3: Export
# ============================================================


def export_google(credentials: list[Credential]) -> str:
    """Google Password Manager CSV format."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["name", "url", "username", "password", "note"])
    for c in credentials:
        writer.writerow([c.title, c.url, c.username, c.password, c.note])
    return buf.getvalue()


def export_bitwarden(credentials: list[Credential]) -> str:
    """Bitwarden CSV format."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "folder", "favorite", "type", "name", "notes", "fields",
        "reprompt", "login_uri", "login_username", "login_password", "login_totp",
    ])
    for c in credentials:
        writer.writerow([
            "",      # folder
            "0",     # favorite
            "1",     # type (login)
            c.title,
            c.note,
            "",      # fields
            "0",     # reprompt
            c.url,
            c.username,
            c.password,
            c.totp,
        ])
    return buf.getvalue()


def export_1password(credentials: list[Credential]) -> str:
    """1Password CSV format (no header row)."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    for c in credentials:
        writer.writerow([c.title, c.url, c.username, c.password, c.note])
    return buf.getvalue()


def export_lastpass(credentials: list[Credential]) -> str:
    """LastPass CSV format."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["url", "username", "password", "totp", "extra", "name", "grouping", "fav"])
    for c in credentials:
        writer.writerow([c.url, c.username, c.password, c.totp, c.note, c.title, "", "0"])
    return buf.getvalue()


def export_keepass(credentials: list[Credential]) -> str:
    """KeePass CSV format."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Account", "Login Name", "Password", "Web Site", "Comments"])
    for c in credentials:
        comments = c.note
        if c.totp:
            comments = f"TOTP: {c.totp}\n{comments}".strip()
        writer.writerow([c.title, c.username, c.password, c.url, comments])
    return buf.getvalue()


def export_dashlane(credentials: list[Credential]) -> str:
    """Dashlane CSV format."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["username", "username2", "username3", "title", "password", "note", "url", "category", "otpSecret"])
    for c in credentials:
        writer.writerow([c.username, "", "", c.title, c.password, c.note, c.url, "", c.totp])
    return buf.getvalue()


EXPORTERS = {
    "google": export_google,
    "bitwarden": export_bitwarden,
    "1password": export_1password,
    "lastpass": export_lastpass,
    "keepass": export_keepass,
    "dashlane": export_dashlane,
}

SUPPORTED_FORMATS = list(EXPORTERS.keys())


# ============================================================
# CLI
# ============================================================


def main():
    parser = argparse.ArgumentParser(
        description="Convert Samsung Pass (.spass) exports to password manager CSV",
        epilog="Supported formats: " + ", ".join(SUPPORTED_FORMATS),
    )
    parser.add_argument("file", help="Path to .spass export file")
    parser.add_argument(
        "--format", "-f",
        choices=SUPPORTED_FORMATS,
        default="google",
        help="Output format (default: google)",
    )
    parser.add_argument("--password", "-p", help="Decryption password (interactive prompt if omitted)")
    parser.add_argument("--output", "-o", help="Output file path (auto-generated if omitted)")
    parser.add_argument("--dump", action="store_true", help="Also save the full decrypted text to a file")

    args = parser.parse_args()

    # Validate input file
    if not os.path.isfile(args.file):
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        sys.exit(1)
    if not args.file.lower().endswith(".spass"):
        print(f"Error: Expected a .spass file: {args.file}", file=sys.stderr)
        sys.exit(1)

    print(DISCLAIMER)
    print()

    # Password input
    password = args.password
    if not password:
        password = getpass.getpass("Enter decryption password: ")
        if not password:
            print("Error: No password provided.", file=sys.stderr)
            sys.exit(1)

    # Layer 1: Decrypt
    print("Decrypting...")
    try:
        with open(args.file, "rb") as f:
            encrypted_data = f.read()
        decrypted_bytes = decrypt_spass(encrypted_data, password)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Decryption error: {e}", file=sys.stderr)
        sys.exit(1)

    decrypted_text = decrypted_bytes.decode("utf-8")
    print(f"Decryption complete ({len(decrypted_bytes):,} bytes)")

    # --dump: save raw decrypted text
    if args.dump:
        dump_path = os.path.splitext(args.file)[0] + ".decrypted.txt"
        with open(dump_path, "w", encoding="utf-8") as f:
            f.write(decrypted_text)
        print(f"Decrypted data saved to: {dump_path}")

    # Layer 2: Parse
    print("Parsing data...")
    credentials, all_tables = parse_credentials(decrypted_text)

    # Display table summary
    if all_tables:
        print(f"\nDetected {len(all_tables)} table(s):")
        for i, table in enumerate(all_tables, 1):
            status = "-> converting" if table.is_credential_table else "-> skipped (not credentials)"
            header_preview = ", ".join(table.headers[:5])
            if len(table.headers) > 5:
                header_preview += "..."
            print(f"  [{i}] {table.row_count} row(s), headers: {header_preview} {status}")
        print()

    print(f"Found {len(credentials)} credential(s)")

    if not credentials:
        print("Warning: No credentials found.", file=sys.stderr)
        if all_tables:
            print("Hint: Use --dump to inspect the full decrypted data.", file=sys.stderr)
        sys.exit(1)

    # Layer 3: Export
    fmt = args.format
    exporter = EXPORTERS[fmt]
    csv_content = exporter(credentials)

    # Output path
    if args.output:
        output_path = args.output
    else:
        base = os.path.splitext(args.file)[0]
        output_path = f"{base}.{fmt}.csv"

    with open(output_path, "w", encoding="utf-8", newline="") as f:
        f.write(csv_content)

    print(f"Exported to: {output_path} ({fmt} format, {len(credentials)} entries)")
    print()
    print("!! IMPORTANT: Securely delete the CSV file after importing !!")


if __name__ == "__main__":
    main()
