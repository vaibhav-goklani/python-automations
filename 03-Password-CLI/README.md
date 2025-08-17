# Password CLI — Local encrypted password vault

A simple single-file Python CLI that stores credentials locally in one encrypted file using a master password. It encrypts the entire vault (a JSON object) with Fernet and derives the encryption key from your master password using PBKDF2‑HMAC‑SHA256 with a per‑vault salt and a high iteration count.

---

## Features

- Single-file vault (default: `~/.passcli.vault`).
- Strong KDF: PBKDF2‑HMAC‑SHA256 with per‑vault salt and configurable iterations.
- Symmetric authenticated encryption (Fernet) for the full vault blob.
- Add, update, list, get (optionally reveal password), delete entries.
- Change master password (re‑encrypts with new salt).
- Export decrypted vault to JSON (with confirmation).
- Atomic writes and restrictive file permissions on non‑Windows systems.

---

## Security notes

- The master password is never stored in plaintext. A derived key (via PBKDF2) is used to encrypt the vault.
- The vault file contains only metadata (KDF, salt, iterations, ciphertext). Actual entries are stored encrypted.
- Treat any exported JSON with extreme care — it contains plaintext passwords.
- The script sets file permissions to `600` on POSIX systems for the temporary file used during writes. You should also protect your user account and backup copies.

---

## Requirements

- Python 3.8+ (should work on 3.8–3.12)
- `cryptography` package

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Installation

Clone or copy `passcli.py` to a folder on your PATH, or run it directly with Python.

Optionally, make it executable and place it in `/usr/local/bin` (POSIX):

```bash
chmod +x passcli.py
sudo mv passcli.py /usr/local/bin/passcli
```

---

## Usage

Basic form:

```bash
python passcli.py [--path VAULT_PATH] <command> [options]
```

Or (if installed as `passcli`):

```bash
passcli [--path VAULT_PATH] <command> [options]
```

### Commands

- `init` — Initialize a new vault.

  - `--force` — overwrite existing file.

- `list` — List entry names.

- `get <name>` — Show metadata for an entry. By default the password is hidden.

  - `--show` — reveal the password in plaintext.

- `add <name>` — Add or update an entry.

  - `--username` — provide username on command line.
  - `--password` — provide password on command line.
  - `--update` — overwrite existing entry.

- `delete <name>` — Delete an entry.

  - `--yes` — skip confirmation prompt.

- `change-master` — Change the master password (re‑encrypts vault with new salt).

- `export` — Print all entries as decrypted JSON to stdout.

  - `--yes` — skip confirmation prompt. **Use with extreme caution.**

### Examples

Initialize a vault (default path `~/.passcli.vault`):

```bash
python passcli.py init
# or
passcli init
```

Add an entry (interactive prompts for missing fields):

```bash
python passcli.py add github --username vaibhav
# prompts for master password and entry password (if not provided)
```

List entries:

```bash
python passcli.py list
```

Show an entry (without revealing password):

```bash
python passcli.py get github
```

Reveal password for an entry:

```bash
python passcli.py get github --show
```

Delete an entry (with confirmation):

```bash
python passcli.py delete github
```

Change master password:

```bash
python passcli.py change-master
```

Export all entries as JSON (dangerous):

```bash
python passcli.py export
```

Use a custom vault path:

```bash
python passcli.py --path ~/secrets/myvault.vault list
```

---

## Vault file format (high level)

The vault file is JSON metadata that looks like this (encrypted blob is base64 token):

```json
{
  "version": 1,
  "kdf": "pbkdf2-hmac-sha256",
  "salt_b64": "...",
  "iterations": 390000,
  "ciphertext": "..."
}
```

After decryption, the plaintext JSON has the structure:

```json
{
  "entries": {
    "github": {
      "username": "vaibhav",
      "password": "xxx",
      "updated_at": 1690000000
    }
  },
  "created_at": 1690000000
}
```

---

## Limitations & TODO

- The entire vault is encrypted as one blob — any change requires re‑encrypting/writing the whole vault.
- No password history, tags, or search — only exact name lookups.
- No clipboard integration or auto‑type features.

---

## Author

`passcli` by Vaibhav Goklani — [https://github.com/vaibhav-goklani](https://github.com/vaibhav-goklani)

Enjoy — and keep your master password safe!
