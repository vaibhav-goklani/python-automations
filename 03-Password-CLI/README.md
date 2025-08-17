# Password CLI

A simple single-file Python CLI that stores everything locally in a single encrypted file using your master password. It uses cryptography (Fernet) with a strong KDF (PBKDF2-HMAC-SHA256) and per-vault salt. The entire vault (a JSON dictionary) is encrypted as one blob.
