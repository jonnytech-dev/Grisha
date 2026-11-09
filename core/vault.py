import json
import sqlite3
import uuid
from dataclasses import dataclass

from core import crypto, storage
from core.auth import Session


@dataclass
class VaultEntry:
    vault_entry_id: str
    title: str
    url: str
    username: str
    password: str
    notes: str

# Builds the AAD label for one vault entry, as bytes
# Ties the encrypted entry to its owner and its own entry id
def _entry_aad(user_id: str, vault_entry_id: str) -> bytes:
    return f"user:{user_id}:entry:{vault_entry_id}".encode()


def _pack(title: str, url: str, username: str, password: str, notes: str) -> bytes:
    # Puts the fields in a dict, turns it into JSON text, then into bytes for encryption
    data = {
        "title": title,
        "url": url,
        "username": username,
        "password": password,
        "notes": notes
    }

    data = json.dumps(data).encode()
    return data

def _unpack(vault_entry_id: str, packed: bytes) -> VaultEntry:
    # Turns the decrypted bytes back into text, then into a dict, then into a VaultEntry
    data = json.loads(packed.decode())
    return VaultEntry(
        vault_entry_id=vault_entry_id,
        title=data["title"],
        url=data["url"],
        username=data["username"],
        password=data["password"],
        notes=data["notes"]
    )

def add_entry(db_connection: sqlite3.Connection, session: Session,
              title: str, url: str, username: str, password: str, notes: str) -> str:
    # Title must be filled to record the new vault entry
    if not title:
        raise ValueError("You must provide a title")

    # Create vault entry ID
    # Made here, before encrypting, so it can go into the AAD
    vault_entry_id = str(uuid.uuid4())
    # Pack the fields together into JSON bytes
    packed = _pack(title, url, username, password, notes)
    # Encrypt the packed fields with the user's DEK and this entry's AAD
    nonce, ciphertext = crypto.encrypt(session.dek, packed, _entry_aad(session.user_id, vault_entry_id)) 

    # Record the encrypted entry into the db
    storage.create_vault_entry(db_connection, vault_entry_id, session.user_id, nonce, ciphertext)
    return vault_entry_id


def get_entry(db_connection: sqlite3.Connection, session: Session, vault_entry_id: str) -> VaultEntry | None:
    # Get the entry only if it belongs to this user, None if not found
    row = storage.get_vault_entry(db_connection, session.user_id, vault_entry_id) 
    if row is None:
        return None

    # Rebuild the same AAD used when the entry was encrypted
    aad = _entry_aad(session.user_id, vault_entry_id)

    # Decrypt with the user's DEK. A swapped or tampered entry raises InvalidTag here.
    packed = crypto.decrypt(session.dek, row["nonce"], row["ciphertext"], aad)
    return _unpack(vault_entry_id, packed)


def list_entries(db_connection: sqlite3.Connection, session: Session) -> list[VaultEntry]:
    rows = storage.get_vault_entries(db_connection, session.user_id)
    entries = []

    for row in rows:
        aad = _entry_aad(session.user_id, row["vault_entry_id"])
        packed = crypto.decrypt(session.dek, row["nonce"], row["ciphertext"], aad)
        unpacked = _unpack(row["vault_entry_id"], packed)
        entries.append(unpacked)

    return entries

def update_entry(db_connection: sqlite3.Connection, session: Session, vault_entry_id: str,
                 title: str, url: str, username: str, password: str, notes: str) -> bool:
    if not title:
        raise ValueError("You must provide a title")

    aad = _entry_aad(session.user_id, vault_entry_id)
    packed = _pack(title, url, username, password, notes)
    nonce, ciphertext = crypto.encrypt(session.dek, packed, aad)

    return storage.update_vault_entry(db_connection, session.user_id, vault_entry_id, nonce, ciphertext)

def delete_entry(db_connection: sqlite3.Connection, session: Session, vault_entry_id: str) -> bool:
    return storage.delete_vault_entry(db_connection, session.user_id, vault_entry_id)