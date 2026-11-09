from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# ========== Links / References / Documentation ==========
# PasswordHasher = https://argon2-cffi.readthedocs.io/en/stable/api.html
# AESGCM = https://cryptography.io/en/latest/hazmat/primitives/aead/


_ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
    encoding='utf-8',
    type=Type.ID
)


def hash_password(password: str) -> str:
    # Creates a hash of a plaintext password entered by the user
    hash = _ph.hash(password)
    return hash


def verify_password(stored_hash: str, password: str) -> bool:
    # Verifies a password entered to the hash stored in the database for that user
    # If successful, it returns True, otherwise False
    # Uses the .verify function rather than the .hash because it reads the salt from the stored hash string.
    try:
        return _ph.verify(stored_hash, password)
    except VerifyMismatchError:
        return False
    except Exception as e:
        print(f'verify_password error: {e}')
        return False

def new_salt() -> bytes:
    # Creates a 16 byte salt 
    return os.urandom(16)

def derive_kek(password: str, salt: bytes) -> bytes:
    # Creates a Key Encryption Key (KEK) derived from the master password. 
    # The KEK is used to encrypt the Data Encryption Key (DEK is randomly generated at account creation)
    # The KEK decrypts the DEK when the user logs in.
    # The KEK is rebuilt from the master password every login.
    # -----
    # The encrypted DEK version (encrypted by the KEK) is stored in the DB.
    # The encrypted DEK gets decrypted at every login by the KEK.
    # The decrypted DEK is dropped from memory when the user logs out.
    # The decrypted DEK is the key that encrypts each password in the vault
    # -----
    # The DEK prevents hundreds of vault password encryption rewrites when a master password is reset.
    # If there was no DEK, each vault password would need to be re-encrypted by master password.
    # If the master password is reset, there is only one encryption key (the KEK) changed, instead of many.
    return hash_secret_raw(
        secret=password.encode('utf-8'), 
        salt=salt, 
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32, # AES-256 standard
        type=Type.ID
    )

def new_dek() -> bytes:
    # Create a random 256 bit (32 byte) key
    dek = AESGCM.generate_key(256)
    return dek

def encrypt(key: bytes, unencrypted_data: bytes, aad: bytes) -> tuple[bytes, bytes]:
    # Encrypts data with AES-GCM using the key passed in.
    # This function is generic. It is used to encrypt the DEK with the KEK, and to encrypt vault passwords with the DEK.
    # aad = adittional authenticated data (AAD). It is unencrypted data you pass in as label (ex. user's uuid)
    # The aad is not hidden, but it is checked. If the aad is changed, decryption fails.
    # -----
    # A new 12 byte nonce is created every time encrypt runs.
    # A nonce must never be reused with the same key.
    # The nonce is not secret. It is stored in the DB next to the encrypted data.
    # Returns the nonce and the encrypted data, since both are needed to decrypt later.

    cipher = AESGCM(key) # Creates the cipher object with the key. Same pattern as PasswordHasher.
    nonce = os.urandom(12)
    
    encrypted_data = cipher.encrypt(nonce, unencrypted_data, aad) # the encrypted DEK derived from the KEK + data (un-encrypted DEK)
    return (nonce, encrypted_data)

def decrypt(key: bytes, nonce: bytes, encrypted_data: bytes, aad: bytes) -> bytes:
    # Decrypts data with AES-GCM using the same key, nonce, and aad used to encrypt it.
    # If the key, nonce, or aad is wrong, or the encrypted data was changed, it raises InvalidTag.
    # InvalidTag is not caught here on purpose. Tampered or wrong data should fail loudly, not return something.
    # The error does not say which part was wrong. This prevents an attacker from learning what they got right.

    cipher = AESGCM(key)
    unencrypted_data = cipher.decrypt(nonce, encrypted_data, aad)
    return unencrypted_data