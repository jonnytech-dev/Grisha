import sqlite3
from pathlib import Path
import uuid

# Create a sqlite3 connection
def db_connect(db_path: Path) -> sqlite3.Connection:
    db_connection = sqlite3.connect(db_path)
    # Enable foreign keys / references
    db_connection.execute("PRAGMA foreign_keys = ON")
    # Enable reading rows by name rather than by position [ex. 0]
    db_connection.row_factory = sqlite3.Row

    return db_connection

# Creates the users table
def create_tables(db_connection: sqlite3.Connection) -> None:
    # kek_salt is used to create KEK that decrypts the encrypted DEK
    db_connection.execute("CREATE TABLE IF NOT EXISTS users(" \
            "user_id TEXT NOT NULL PRIMARY KEY, " \
            "username TEXT UNIQUE NOT NULL," \
            "email TEXT UNIQUE NOT NULL, " \
            "password_hash TEXT NOT NULL, " \
            "role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('admin', 'user')), " \
            "encrypted_dek BLOB NOT NULL, " \
            "encrypted_dek_nonce BLOB NOT NULL," \
            "kek_salt BLOB NOT NULL, " \
            "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, " \
            "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ")" \
    )

    # Creates the entries table 
    db_connection.execute("CREATE TABLE IF NOT EXISTS vault_entries(" \
            "vault_entry_id TEXT NOT NULL PRIMARY KEY, " \
            "user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE, " \
            "nonce BLOB NOT NULL, " \
            "ciphertext BLOB NOT NULL, " \
            "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, " \
            "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP" \
        ")"
    )

    # Creates the login attempts table 
    db_connection.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts(
            login_attempt_id INTEGER NOT NULL PRIMARY KEY,
            ip_address TEXT,
            email TEXT NOT NULL,
            success INTEGER NOT NULL CHECK (success in (0, 1)),
            attempted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )"""
    )

    # Creates the register attempts table 
    db_connection.execute("""
        CREATE TABLE IF NOT EXISTS register_attempts(
            register_attempt_id INTEGER NOT NULL PRIMARY KEY,
            ip_address TEXT,
            attempted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )"""
    )

    # Create index for emails for login attempts
    db_connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_login_email_time
        ON login_attempts (email, attempted_at)
    """)

    # Create index for ip_addres for login attempts
    db_connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_login_ip_time
        ON login_attempts (ip_address, attempted_at)
    """)

    # Create index for ip_address for new account registers
    db_connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_register_ip_time
        ON register_attempts (ip_address, attempted_at)
    """)

    # Commit the table creations
    db_connection.commit()

# Create a new user
def create_user(
        db_connection: sqlite3.Connection,
        user_id: str,
        username: str,
        email: str,
        password_hash: str,
        encrypted_dek: bytes,
        encrypted_dek_nonce: bytes,
        kek_salt: bytes,
        role: str = "user"
    ) -> None:

        user_data = (
            user_id,
            username,
            email.lower(),
            password_hash,
            role,
            encrypted_dek,
            encrypted_dek_nonce,
            kek_salt
        )

        db_connection.execute("INSERT INTO users (user_id, username, email, password_hash, role, encrypted_dek, encrypted_dek_nonce, kek_salt) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", user_data)
        db_connection.commit()

# GET a user by email
def find_email(db_connection: sqlite3.Connection, email: str) -> sqlite3.Row | None:
    user = db_connection.execute("SELECT user_id, role, password_hash, kek_salt, encrypted_dek, encrypted_dek_nonce FROM users WHERE email = ?", (email.lower(), )).fetchone()
    return user

# Create a new vault entry connected to a user
def create_vault_entry(
    db_connection: sqlite3.Connection,
    vault_entry_id, # must be passed in since the encryption uses the vault_entry_id as the AAD(label)
    user_id: str,
    nonce: bytes,
    ciphertext: bytes,
) -> None:

    db_connection.execute('INSERT INTO vault_entries (vault_entry_id, user_id, nonce, ciphertext) VALUES (?, ?, ?, ?)', (vault_entry_id, user_id, nonce, ciphertext))
    db_connection.commit()
    

def get_vault_entries(db_connection: sqlite3.Connection, user_id: str) -> list[sqlite3.Row]:
    vault_entries_result = db_connection.execute("SELECT vault_entry_id, nonce, ciphertext FROM vault_entries WHERE user_id = ?", (user_id, )).fetchall()
    return vault_entries_result


def get_vault_entry(db_connection: sqlite3.Connection, user_id: str, vault_entry_id: str) -> sqlite3.Row | None:
    vault_entry_result = db_connection.execute("SELECT vault_entry_id, nonce, ciphertext FROM vault_entries WHERE user_id = ? AND vault_entry_id = ?", (user_id, vault_entry_id)).fetchone()
    return vault_entry_result


def update_vault_entry(
    db_connection: sqlite3.Connection,
    user_id: str,
    vault_entry_id: str,
    nonce: bytes,
    ciphertext: bytes,
) -> bool:
    # Get the stored entry data first
    # If no entry exist, it returns None, this function returns False immediately
    if get_vault_entry(db_connection, user_id, vault_entry_id):
        db_connection.execute("UPDATE vault_entries SET nonce = ?, ciphertext = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ? AND vault_entry_id = ?", (nonce, ciphertext, user_id, vault_entry_id))
        db_connection.commit()
        return True
    else: return False

def delete_vault_entry(db_connection: sqlite3.Connection, user_id: str, vault_entry_id: str) -> bool:
    # Check if entry exist, return False if not
    if not get_vault_entry(db_connection, user_id, vault_entry_id): return False 

    # If entry exist, delete and commit
    delete = db_connection.execute("DELETE FROM vault_entries WHERE user_id = ? AND vault_entry_id = ?", (user_id, vault_entry_id))
    db_connection.commit()

    if delete.rowcount == 1: return True
    else: return False

# =============================================================
# Record and count login and register attempts

def record_login_attempt(db_connection: sqlite3.Connection, ip_address: str, email: str, success: bool) -> None:
    email = email.lower()
    db_connection.execute("INSERT INTO login_attempts (ip_address, email, success, attempted_at) VALUES (?, ?, ?, datetime('now'))", (ip_address, email, success))
    db_connection.commit()

def record_register_attempt(db_connection: sqlite3.Connection, ip_address: str) -> None:
    db_connection.execute("INSERT INTO register_attempts (ip_address, attempted_at) VALUES (?, datetime('now'))", (ip_address, ))
    db_connection.commit()

def count_recent_logins_by_email(db_connection: sqlite3.Connection, email: str, minutes: int) -> int:
    email = email.lower()
    email_count = db_connection.execute("SELECT COUNT(*) AS failures FROM login_attempts WHERE email = ? AND success = 0 AND attempted_at > datetime('now', ?)", (email, f"-{minutes} minutes")).fetchone()[0]
    return email_count

def count_recent_logins_by_ip_address(db_connection: sqlite3.Connection, ip_address: str, minutes: int) -> int:
    ip_count = db_connection.execute("SELECT COUNT(*) AS failures FROM login_attempts WHERE ip_address = ? AND success = 0 AND attempted_at > datetime('now', ?)", (ip_address, f"-{minutes} minutes")).fetchone()[0]
    return ip_count

def count_recent_registers_by_ip_address(db_connection: sqlite3.Connection, ip_address: str, minutes: int) -> int:
    ip_count = db_connection.execute("SELECT COUNT(*) AS failures FROM register_attempts WHERE ip_address = ? AND attempted_at > datetime('now', ?)", (ip_address, f"-{minutes} minutes")).fetchone()[0]
    return ip_count

# ==============================================================