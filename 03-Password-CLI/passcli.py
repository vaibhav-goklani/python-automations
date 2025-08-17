#!/usr/bin/env python3
"""
passcli.py - A simple local encrypted password vault (single file).

Features:
- Securely stores passwords and usernames in a single encrypted file.
- Uses PBKDF2-HMAC-SHA256 for key derivation and Fernet for encryption.
- Supports adding, updating, deleting, listing, exporting, and retrieving entries.
- Allows changing the master password with re-encryption.
- Interactive and informative command-line interface.

Usage:
    python passcli.py [--path VAULT_PATH] <command> [options]

Commands:
    init            Initialize a new vault
    list            List all entry names
    get             Show entry metadata (optionally reveal password)
    add             Add or update an entry
    delete          Delete an entry
    change-master   Change the master password
    export          Export all entries as decrypted JSON

Author: https://www.github.com/vaibhav-goklani
"""

import argparse, base64, json, os, sys, getpass, time
from pathlib import Path
from typing import Dict, Any
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken

VAULT_VERSION = 1

def derive_key(password: str, salt: bytes, iterations: int = 390000) -> bytes:
    """
    Derive a Fernet key from a password and salt using PBKDF2-HMAC-SHA256.

    Args:
        password (str): The master password.
        salt (bytes): The salt.
        iterations (int): Number of PBKDF2 iterations.

    Returns:
        bytes: The derived Fernet key.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))

def new_salt(n: int = 16) -> bytes:
    """Generate a new random salt."""
    return os.urandom(n)

def secure_write(path: Path, data: bytes):
    """
    Write data atomically to a file and set restrictive permissions.

    Args:
        path (Path): The file path.
        data (bytes): Data to write.
    """
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
    if os.name != "nt":
        os.chmod(tmp, 0o600)
    os.replace(tmp, path)

def load_vault_bytes(vault_path: Path) -> Dict[str, Any]:
    """
    Load and parse the vault file as JSON.

    Args:
        vault_path (Path): Path to the vault file.

    Returns:
        dict: The vault metadata.

    Exits if the vault is missing or corrupt.
    """
    if not vault_path.exists():
        sys.exit(f"[!] Vault not found: {vault_path}. Run `init` first.")
    with open(vault_path, "rb") as f:
        raw = f.read()
    try:
        meta = json.loads(raw.decode("utf-8"))
    except Exception:
        sys.exit("[!] Vault file is corrupt or not JSON.")
    for field in ("version", "kdf", "salt_b64", "iterations", "ciphertext"):
        if field not in meta:
            sys.exit(f"[!] Vault header missing field: {field}")
    return meta

def decrypt_vault(vault_path: Path, password: str) -> Dict[str, Any]:
    """
    Decrypt the vault file using the provided password.

    Args:
        vault_path (Path): Path to the vault file.
        password (str): Master password.

    Returns:
        tuple: (vault data dict, vault metadata dict)

    Exits if decryption fails.
    """
    meta = load_vault_bytes(vault_path)
    if meta["kdf"] != "pbkdf2-hmac-sha256":
        sys.exit("[!] Unsupported KDF.")
    salt = base64.urlsafe_b64decode(meta["salt_b64"])
    key = derive_key(password, salt, meta["iterations"])
    f = Fernet(key)
    try:
        plaintext = f.decrypt(meta["ciphertext"].encode("utf-8"))
    except InvalidToken:
        sys.exit("[!] Invalid master password or vault tampered.")
    try:
        data = json.loads(plaintext.decode("utf-8"))
    except Exception:
        sys.exit("[!] Decrypted data is not valid JSON.")
    if not isinstance(data, dict) or "entries" not in data:
        sys.exit("[!] Vault structure invalid.")
    return data, meta

def encrypt_vault(vault_path: Path, password: str, data: Dict[str, Any], salt: bytes = None, iterations: int = 390000):
    """
    Encrypt and write the vault data.

    Args:
        vault_path (Path): Path to the vault file.
        password (str): Master password.
        data (dict): Vault data to encrypt.
        salt (bytes): Salt to use (optional).
        iterations (int): PBKDF2 iterations.
    """
    if salt is None:
        salt = new_salt()
    key = derive_key(password, salt, iterations)
    f = Fernet(key)
    plaintext = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    token = f.encrypt(plaintext)
    meta = {
        "version": VAULT_VERSION,
        "kdf": "pbkdf2-hmac-sha256",
        "salt_b64": base64.urlsafe_b64encode(salt).decode("ascii"),
        "iterations": iterations,
        "ciphertext": token.decode("ascii"),
    }
    secure_write(vault_path, json.dumps(meta, ensure_ascii=False, indent=2).encode("utf-8"))

def ensure_default_path(path_opt: str) -> Path:
    """
    Resolve the vault file path, using default if not specified.

    Args:
        path_opt (str): Optional path.

    Returns:
        Path: Resolved path.
    """
    if path_opt:
        return Path(path_opt).expanduser().resolve()
    default = Path.home() / ".passcli.vault"
    return default

def input_hidden(prompt: str) -> str:
    """
    Prompt for input with hidden echo (for passwords).

    Args:
        prompt (str): Prompt string.

    Returns:
        str: User input.
    """
    try:
        return getpass.getpass(prompt)
    except Exception:
        return input(prompt)

def cmd_init(args):
    """Initialize a new vault."""
    vault_path = ensure_default_path(args.path)
    if vault_path.exists() and not args.force:
        sys.exit(f"[!] File already exists: {vault_path}. Use --force to overwrite.")
    print("[*] Initializing new vault...")
    pw1 = input_hidden("Create master password: ")
    pw2 = input_hidden("Confirm master password: ")
    if pw1 != pw2:
        sys.exit("[!] Passwords do not match. Aborting.")
    data = {"entries": {}, "created_at": int(time.time())}
    encrypt_vault(vault_path, pw1, data)
    print(f"[+] Initialized new vault at {vault_path}")

def cmd_list(args):
    """List all entry names in the vault."""
    vault_path = ensure_default_path(args.path)
    password = input_hidden("Master password: ")
    print("[*] Decrypting vault...")
    data, _ = decrypt_vault(vault_path, password)
    entries = data["entries"]
    if not entries:
        print("(empty)")
        return
    print("[*] Entries in vault:")
    for name in sorted(entries):
        meta = entries[name]
        user = meta.get("username", "")
        print(f"- {name}" + (f"  (user: {user})" if user else ""))

def cmd_get(args):
    """Show entry metadata and optionally reveal password."""
    vault_path = ensure_default_path(args.path)
    password = input_hidden("Master password: ")
    print(f"[*] Retrieving entry '{args.name}'...")
    data, _ = decrypt_vault(vault_path, password)
    entry = data["entries"].get(args.name)
    if not entry:
        sys.exit("[!] No such entry.")
    print(f"name: {args.name}")
    if entry.get("username"): print(f"username: {entry['username']}")
    if args.show:
        print(f"password: {entry['password']}")
    else:
        print("password: (hidden)  Use --show to reveal")

def cmd_add(args):
    """Add or update an entry in the vault."""
    vault_path = ensure_default_path(args.path)
    password = input_hidden("Master password: ")
    print(f"[*] Adding/updating entry '{args.name}'...")
    data, meta = decrypt_vault(vault_path, password)
    if args.name in data["entries"] and not args.update:
        sys.exit("[!] Entry exists. Use --update to overwrite.")
    username = args.username or input("username (optional): ").strip()
    pw = args.password or input_hidden("password: ")
    data["entries"][args.name] = {"username": username, "password": pw, "updated_at": int(time.time())}
    encrypt_vault(vault_path, password, data, salt=base64.urlsafe_b64decode(meta["salt_b64"]), iterations=meta["iterations"])
    print(f"[+] Saved entry '{args.name}'.")

def cmd_delete(args):
    """Delete an entry from the vault."""
    vault_path = ensure_default_path(args.path)
    password = input_hidden("Master password: ")
    print(f"[*] Deleting entry '{args.name}'...")
    data, meta = decrypt_vault(vault_path, password)
    if args.name not in data["entries"]:
        sys.exit("[!] No such entry.")
    if not args.yes:
        confirm = input(f"Are you sure you want to delete '{args.name}'? (y/N): ").lower()
        if confirm != "y":
            sys.exit("[!] Deletion cancelled.")
    del data["entries"][args.name]
    encrypt_vault(vault_path, password, data, salt=base64.urlsafe_b64decode(meta["salt_b64"]), iterations=meta["iterations"])
    print(f"[+] Deleted entry '{args.name}'.")

def cmd_change_master(args):
    """Change the master password and re-encrypt the vault."""
    vault_path = ensure_default_path(args.path)
    old = input_hidden("Current master password: ")
    print("[*] Verifying current password...")
    data, _ = decrypt_vault(vault_path, old)
    new1 = input_hidden("New master password: ")
    new2 = input_hidden("Confirm new master password: ")
    if new1 != new2:
        sys.exit("[!] Passwords do not match. Aborting.")
    print("[*] Re-encrypting vault with new master password and salt...")
    encrypt_vault(vault_path, new1, data)
    print("[+] Master password changed and vault re-encrypted with a new salt.")

def cmd_export(args):
    """
    Export decrypted entries to stdout as JSON (use carefully).

    WARNING: This will print all passwords in plain text!
    """
    vault_path = ensure_default_path(args.path)
    password = input_hidden("Master password: ")
    print("[*] Exporting all entries as decrypted JSON...")
    data, _ = decrypt_vault(vault_path, password)
    if not args.yes:
        confirm = input(f"Are you sure you want to export? (y/N): ").lower()
        if confirm != "y":
            sys.exit("[!] Export cancelled.")
    print(json.dumps(data["entries"], indent=2, ensure_ascii=False))

def build_parser():
    """Build the command-line argument parser."""
    p = argparse.ArgumentParser(
        description="Local encrypted password vault (single file)."
    )
    p.add_argument("--path", help="Path to vault file (default: ~/.passcli.vault)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("init", help="Initialize new vault")
    sp.add_argument("--force", action="store_true", help="Overwrite if exists")
    sp.set_defaults(func=cmd_init)

    sp = sub.add_parser("list", help="List entry names")
    sp.set_defaults(func=cmd_list)

    sp = sub.add_parser("get", help="Show metadata, hide password by default")
    sp.add_argument("name")
    sp.add_argument("--show", action="store_true", help="Reveal password")
    sp.set_defaults(func=cmd_get)

    sp = sub.add_parser("add", help="Add or update an entry")
    sp.add_argument("name")
    sp.add_argument("--username")
    sp.add_argument("--password")
    sp.add_argument("--update", action="store_true", help="Overwrite if exists")
    sp.set_defaults(func=cmd_add)

    sp = sub.add_parser("delete", help="Delete an entry")
    sp.add_argument("name")
    sp.add_argument("--yes", action="store_true", help="Confirms deletion without prompt")
    sp.set_defaults(func=cmd_delete)

    sp = sub.add_parser("change-master", help="Change the master password")
    sp.set_defaults(func=cmd_change_master)

    sp = sub.add_parser("export", help="Export all entries as JSON (DECRYPTED) to stdout")
    sp.add_argument("--yes", action="store_true", help="Confirms export without prompt")
    sp.set_defaults(func=cmd_export)

    return p

def main():
    """Main entry point."""
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
