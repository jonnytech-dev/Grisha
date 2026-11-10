import sqlite3
from core import crypto, storage
import uuid
import string
from dataclasses import dataclass

MAX_FAILED_LOGIN_ATTEMPTS=10
MAX_FAILED_REGISTER_ATTEMPTS=5

# ---------- Custom error exceptions ----------
# Username or email is already taken
class UserExistsError(Exception):
    pass

# Wrong email or password when attempting to login
class InvalidCredentialsError(Exception):
    pass

# Too many login attempts error
class AccountLockedError(Exception):
    pass

# ---------- Data Formats ----------
# Data format that login should return
@dataclass
class Session:
    user_id: str
    role: str
    dek: bytes

# ---------- Register & Login ----------

# Password requirement characters
strong_characters = string.digits + string.punctuation

# Register a new user
# Registeration attempts do not get logged for password failures
def register(db_connection: sqlite3.Connection, username: str, email: str, password: str, ip_address: str | None = None) -> str:
    # Check if user is blocked from making too many request
    if storage.count_recent_registers_by_ip_address(db_connection, ip_address, 15) >= MAX_FAILED_REGISTER_ATTEMPTS:
        raise AccountLockedError("Too many register attempts")
        
    # Verify password is strong/secure
    if len(password) < 12 : raise ValueError("Password must be atleast 12 characters")
    elif len(password) > 256: raise ValueError("Password must not be more than 256 characters")

    # Create data
    user_id = str(uuid.uuid4())
    password_hash = crypto.hash_password(password)
    kek_salt = crypto.new_salt()
    kek = crypto.derive_kek(password, kek_salt)
    dek = crypto.new_dek()

    # Encrypt
    encrypted_data = crypto.encrypt(kek, dek, aad = f"user:{user_id}:dek".encode())
    encrypted_dek_nonce, encrypted_dek = encrypted_data
    
    # Return user_id if successful
    try:
        storage.create_user(db_connection, user_id, username, email, password_hash, encrypted_dek, encrypted_dek_nonce, kek_salt)
        # Record register attempt
        storage.record_register_attempt(db_connection, ip_address)

    except sqlite3.IntegrityError:
        # Record register attempt
        storage.record_register_attempt(db_connection, ip_address)
        raise UserExistsError("Username or Email already exists")

    return user_id

# A real Argon2 hash of a throwaway value, used to keep timing the same for unknown emails
_DUMMY_HASH = crypto.hash_password("dummy-password-for-timing")

def login(db_connection: sqlite3.Connection, email: str, password: str, ip_address: str | None = None, ) -> Session:
    # Check if user is blocked from making too many request
    if storage.count_recent_logins_by_ip_address(db_connection, ip_address, 15) >= MAX_FAILED_LOGIN_ATTEMPTS or storage.count_recent_logins_by_email(db_connection, email, 15) >= MAX_FAILED_LOGIN_ATTEMPTS:
        raise AccountLockedError("Too many login attempts")

    # Find user by email
    user = storage.get_user_by_email(db_connection, email)

    # If user does not exist, hash the dummy password to prevent attackers from using time measuring
    if user is None:
        # Check if password provided matches the password hash stored
        crypto.verify_password(_DUMMY_HASH, password)
        # Record register attempt
        storage.record_login_attempt(db_connection, ip_address, email, 0)
        raise InvalidCredentialsError("Incorrect email or password")
        
    if crypto.verify_password(user["password_hash"], password) == False:
        storage.record_login_attempt(db_connection, ip_address, email, 0)
        raise InvalidCredentialsError("Incorrect email or password")

    # Derive the KEK by the provided password and the stored salt
    kek = crypto.derive_kek(password, user["kek_salt"])
    # Decrypt the encrypted DEK to get the plain DEK
    dek = crypto.decrypt(kek, user["encrypted_dek_nonce"], user["encrypted_dek"], aad = f"user:{user['user_id']}:dek".encode())

    # Record login attempt as successful
    storage.record_login_attempt(db_connection, ip_address, email, 1)

    # Return the session data to the caller (server code)
    # DEK stays in server memory, never stored in the DB or remembered after logout
    return Session(user["user_id"], user["role"], dek)