# Vaultix

A secure, multi-user password management tool built in Python. Vaultix combines password management, password generation, and password strength analysis into a single CLI application. It uses AES-256-GCM encryption, PBKDF2 key derivation, and Windows Hello biometric authentication to protect your credentials.

---

## Features

- **Multi-user support** — multiple users can register and manage their own separate vaults
- **AES-256-GCM encryption** — every password is encrypted before being stored in the database
- **Windows Hello authentication** — biometric or PIN-based login, no need to type your master password every time
- **Password generation** — generates cryptographically secure passwords with guaranteed character class requirements
- **Password strength analysis** — scores passwords using zxcvbn entropy estimation and checks them against the HaveIBeenPwned breach database
- **CSV import/export** — backup or migrate your vault entries
- **Session timeout** — automatically locks the session after 5 minutes of inactivity
- **Clipboard auto-clear** — copies passwords to the clipboard and clears them after 5 minutes

---

## Requirements

- Windows (required for Windows Hello and clipboard integration)
- Python 3.13+
- The following external libraries (install via `pip install -r requirements.txt`):

```
pywin32
pwinput
pyfiglet
pycryptodome
keyring
requests
tabulate
zxcvbn
```

---

## Installation

```bash
git clone <repository>
cd vaultix
pip install -r requirements.txt
python project.py
```

The database file (`database.db`) is created automatically on first run.

---

## Usage

Run the tool:

```bash
python project.py
```

On launch you will be presented with the main menu:

```
[1] Register
[2] Log in (login)
[3] Exit
```

### Registering

1. Choose `[1] Register`
2. Set a username
3. Set a master password — this is used **once** to derive your encryption key via PBKDF2. You will not need it again to access the tool
4. The derived encryption key is stored securely in Windows Credential Manager
5. After registration, log in using Windows Hello

### Logging In

1. Choose `[2] Log in`
2. Enter your username
3. Authenticate via Windows Hello (fingerprint, face, or PIN)
4. On success, you are granted access to the vault

### Features Menu

Once logged in, the following features are available:

| Option | Feature |
|--------|---------|
| 1 | Retrieve a password (copied to clipboard) |
| 2 | Add a new record |
| 3 | Generate a new record |
| 4 | Update an existing record |
| 5 | Delete a record |
| 6 | Retrieve all records |
| 7 | Export vault to a CSV file |
| 8 | Import records from a CSV file |
| 9 | Check password strength |
| 10 | Delete current user |

---

## Project Structure

### `database.py`

The lowest layer of the application. Contains the `Database` class which is the only component that directly communicates with the SQLite database. It handles all queries — creating tables, adding, retrieving, updating, and deleting users and password entries. It does not encrypt, decrypt, or display anything. It is purely a query layer.

The database contains two tables:

- **users** — stores the username and salt for each registered user
- **passwords** — stores the encrypted password, nonce, and authentication tag for each entry, linked to a user via a foreign key

### `vault.py`

The middle layer between the database and the UI. Contains the `Vault` class which is responsible for all encryption and decryption using AES-256-GCM mode. Every password is encrypted before being passed to `database.py` for storage, and decrypted after being retrieved.

AES-256-GCM provides both encryption and authentication — each encrypted password has a corresponding nonce and tag stored alongside it. On retrieval, the tag is verified to ensure the password has not been tampered with.

`Vault` also handles CSV export and import, and uses regular expressions to validate file extensions.

### `users.py`

Handles all user authentication logic. Contains three main functions:

- **`register`** — creates a new user, generates a random salt, derives a 256-bit encryption key using PBKDF2-HMAC-SHA256 with 600,000 iterations, and stores the key in Windows Credential Manager
- **`login`** — verifies the username exists, triggers Windows Hello authentication via a PowerShell script, and retrieves the encryption key from Windows Credential Manager on success
- **`delete`** — authenticates the user via Windows Hello, deletes all their password entries, removes their record from the database, and deletes their encryption key from Windows Credential Manager

The master password is never stored anywhere. It is used once during registration to derive the encryption key and then discarded.

### `generator.py`

Responsible for generating cryptographically secure random passwords using Python's `secrets` module. The `generate` function accepts a length parameter (minimum 12) and guarantees the generated password contains at least 3 lowercase letters, 3 uppercase letters, 3 digits, and 3 special characters. The remaining characters are filled randomly from the full pool. The final password is shuffled using `secrets.SystemRandom()` to eliminate any positional patterns.

### `helpers.py`

A collection of utility functions used across multiple files:

- **`copy_to_clipboard`** — copies a password to the Windows clipboard
- **`clear_clipboard`** — clears the clipboard after a given number of seconds using a background daemon thread
- **`windows_hello_auth`** — triggers the Windows Hello authentication prompt via a PowerShell script using the `UserConsentVerifier` WinRT API
- **`confirmation`** — prompts the user for a yes/no confirmation before destructive operations
- **`check_strength`** — evaluates a password's strength using the `zxcvbn` library (score 0–4, warnings, suggestions, estimated crack time) and checks it against the HaveIBeenPwned API using k-anonymity to preserve privacy
- **`update_activity`** — manages session timeout by restarting a 5-minute timer on each user action

### `project.py`

The UI layer. Responsible for all user interaction — printing menus, validating inputs, catching exceptions, and translating them into user-friendly messages. It never implements business logic directly; it delegates all operations to the appropriate module.

The UI follows a menu-driven structure:

- **`main`** — entry point, handles the register/login flow
- **`greeting`** — prints the main menu and returns the user's choice
- **`service`** — prints the features menu and returns the user's choice
- **`service_logic`** — maps each feature choice to its corresponding function and manages session continuity
- Individual functions (`add_record`, `retrieve_pswd`, `generate_record`, etc.) handle the input prompts and output display for each feature

---

## Security Design

| Concern | Approach |
|---------|---------|
| Password storage | AES-256-GCM — encrypted at rest, never stored in plaintext |
| Key derivation | PBKDF2-HMAC-SHA256, 600,000 iterations, 16-byte random salt |
| Key storage | Windows Credential Manager, protected by the OS |
| Authentication | Windows Hello (biometric or PIN) |
| Clipboard | Auto-cleared after 5 minutes via background thread |
| Breach detection | HaveIBeenPwned k-anonymity API — only first 5 chars of SHA1 hash are sent |
| Tamper detection | AES-GCM authentication tag verified on every retrieval |
| Session security | Auto-lock after 5 minutes of inactivity |
| CSV export | Plaintext warning displayed before export |

---

## Limitations

- Windows only — Windows Hello and `pywin32` are not available on other platforms
- Clipboard history (Win+V) may retain passwords even after auto-clear, as Windows clipboard history is managed separately by the OS
- The clipboard auto-clear thread is tied to the program's lifetime — if the program is closed before the timer expires, the clipboard is not cleared
