from core import storage
import os
import pytest
import sqlite3
import uuid


def setup_db(tmp_path):
    # Fresh DB with tables for each test
    db_connection = storage.db_connect(tmp_path / "test.db")
    storage.create_tables(db_connection)
    return db_connection


def make_user(db_connection, username, public_key=None):
    # Creates a user with fake keys through storage.create_user, returns the user_id
    user_id = str(uuid.uuid4())
    storage.create_user(
        db_connection,
        user_id=user_id,
        username=username,
        email=f"{username}@example.com",
        password_hash="$argon2id$fake",
        encrypted_dek=os.urandom(48),
        encrypted_dek_nonce=os.urandom(12),
        kek_salt=os.urandom(16),
        public_key=public_key or os.urandom(32),
        encrypted_private_key=os.urandom(48),
        private_key_nonce=os.urandom(12),
    )
    return user_id


def make_vault(db_connection, owner_id, member_role="view"):
    # Creates a vault and adds the owner as a member, returns the vault_id
    vault_id = str(uuid.uuid4())
    storage.create_vault(db_connection, vault_id, "Test Vault", owner_id, member_role)
    storage.create_vault_share(db_connection, vault_id, owner_id, os.urandom(92))
    return vault_id


def make_entry(db_connection, vault_id, created_by):
    # Creates an entry in a vault, returns the vault_entry_id
    vault_entry_id = str(uuid.uuid4())
    storage.create_vault_entry(db_connection, vault_entry_id, vault_id, created_by,
                               os.urandom(48), os.urandom(12), os.urandom(12), os.urandom(60))
    return vault_entry_id


# ========== Users with keys ==========

class Test_Users_With_Keys:
    # get_user_by_email returns the locked private key so login can unlock it
    def test_get_user_by_email_returns_private_key_fields(self, tmp_path):
        db_connection = setup_db(tmp_path)
        user_id = str(uuid.uuid4())
        encrypted_private_key = os.urandom(48)
        private_key_nonce = os.urandom(12)
        storage.create_user(
            db_connection, user_id=user_id, username="jon", email="jon@example.com",
            password_hash="$argon2id$fake", encrypted_dek=os.urandom(48),
            encrypted_dek_nonce=os.urandom(12), kek_salt=os.urandom(16),
            public_key=os.urandom(32), encrypted_private_key=encrypted_private_key,
            private_key_nonce=private_key_nonce,
        )

        user = storage.get_user_by_email(db_connection, "jon@example.com")
        assert user["encrypted_private_key"] == encrypted_private_key
        assert user["private_key_nonce"] == private_key_nonce
        db_connection.close()

    # get_public_key returns exactly the saved public key
    def test_get_public_key(self, tmp_path):
        db_connection = setup_db(tmp_path)
        public_key = os.urandom(32)
        brock = make_user(db_connection, "brock", public_key=public_key)

        assert storage.get_public_key(db_connection, brock) == public_key
        db_connection.close()

    # Unknown user has no public key
    def test_get_public_key_unknown_user(self, tmp_path):
        db_connection = setup_db(tmp_path)

        assert storage.get_public_key(db_connection, str(uuid.uuid4())) is None
        db_connection.close()


# ========== Vaults ==========

class Test_Vaults:
    # An owner with a share row can read entries in their new vault
    def test_owner_can_read_new_vault(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_user(db_connection, "jon")
        vault = make_vault(db_connection, jon)
        entry = make_entry(db_connection, vault, jon)

        row = storage.get_vault_entry(db_connection, jon, entry)
        assert row is not None
        assert row["owner_id"] == jon
        db_connection.close()

    # Only 'edit' or 'view' are allowed as the vault's member_role
    def test_invalid_member_role_fails(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_user(db_connection, "jon")

        with pytest.raises(sqlite3.IntegrityError):
            storage.create_vault(db_connection, str(uuid.uuid4()), "Bad", jon, "admin")
        db_connection.close()

    # A vault's owner must be a real user
    def test_vault_owner_must_exist(self, tmp_path):
        db_connection = setup_db(tmp_path)

        with pytest.raises(sqlite3.IntegrityError):
            storage.create_vault(db_connection, str(uuid.uuid4()), "Ghost", str(uuid.uuid4()))
        db_connection.close()


# ========== Vault shares ==========

class Test_Vault_Shares:
    # A new member can see the vault's entries
    def test_new_member_sees_entries(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_user(db_connection, "jon")
        brock = make_user(db_connection, "brock")
        vault = make_vault(db_connection, jon)
        entry = make_entry(db_connection, vault, jon)

        storage.create_vault_share(db_connection, vault, brock, os.urandom(92))

        assert storage.get_vault_entry(db_connection, brock, entry) is not None
        db_connection.close()

    # Adding the same person to the same vault twice is rejected
    def test_duplicate_share_fails(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_user(db_connection, "jon")
        brock = make_user(db_connection, "brock")
        vault = make_vault(db_connection, jon)
        storage.create_vault_share(db_connection, vault, brock, os.urandom(92))

        with pytest.raises(sqlite3.IntegrityError):
            storage.create_vault_share(db_connection, vault, brock, os.urandom(92))
        db_connection.close()

    # Can't share with someone who doesn't exist
    def test_share_with_unknown_user_fails(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_user(db_connection, "jon")
        vault = make_vault(db_connection, jon)

        with pytest.raises(sqlite3.IntegrityError):
            storage.create_vault_share(db_connection, vault, str(uuid.uuid4()), os.urandom(92))
        db_connection.close()

    # A role override is saved and used
    def test_share_role_override(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_user(db_connection, "jon")
        kim = make_user(db_connection, "kim")
        vault = make_vault(db_connection, jon, member_role="view")
        entry = make_entry(db_connection, vault, jon)

        storage.create_vault_share(db_connection, vault, kim, os.urandom(92), role="edit")

        assert storage.get_vault_entry(db_connection, kim, entry)["role"] == "edit"
        db_connection.close()


# ========== Vault entries ==========

class Test_Vault_Entries_Write:
    # Saved values come back exactly the same
    def test_create_vault_entry_round_trip(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_user(db_connection, "jon")
        vault = make_vault(db_connection, jon)

        entry = str(uuid.uuid4())
        wrapped_entry_key = os.urandom(48)
        ciphertext = os.urandom(60)
        storage.create_vault_entry(db_connection, entry, vault, jon, wrapped_entry_key,
                                   os.urandom(12), os.urandom(12), ciphertext)

        row = storage.get_vault_entry(db_connection, jon, entry)
        assert row["wrapped_entry_key"] == wrapped_entry_key
        assert row["ciphertext"] == ciphertext
        db_connection.close()

    # An entry must belong to a real vault
    def test_entry_needs_real_vault(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_user(db_connection, "jon")

        with pytest.raises(sqlite3.IntegrityError):
            make_entry(db_connection, str(uuid.uuid4()), jon)
        db_connection.close()


# ========== Entry shares ==========

class Test_Entry_Shares_Write:
    # A direct share is readable through get_shared_entry
    def test_create_entry_share(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_user(db_connection, "jon")
        amy = make_user(db_connection, "amy")
        vault = make_vault(db_connection, jon)
        entry = make_entry(db_connection, vault, jon)
        amys_copy = os.urandom(92)

        storage.create_entry_share(db_connection, entry, amy, amys_copy, role="edit")

        row = storage.get_shared_entry(db_connection, amy, entry)
        assert row["wrapped_entry_key"] == amys_copy
        assert row["role"] == "edit"
        db_connection.close()

    # Direct shares default to view
    def test_entry_share_defaults_to_view(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_user(db_connection, "jon")
        amy = make_user(db_connection, "amy")
        vault = make_vault(db_connection, jon)
        entry = make_entry(db_connection, vault, jon)

        storage.create_entry_share(db_connection, entry, amy, os.urandom(92))

        assert storage.get_shared_entry(db_connection, amy, entry)["role"] == "view"
        db_connection.close()

    # Only 'edit' or 'view' are allowed on a direct share
    def test_invalid_entry_share_role_fails(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_user(db_connection, "jon")
        amy = make_user(db_connection, "amy")
        vault = make_vault(db_connection, jon)
        entry = make_entry(db_connection, vault, jon)

        with pytest.raises(sqlite3.IntegrityError):
            storage.create_entry_share(db_connection, entry, amy, os.urandom(92), role="owner")
        db_connection.close()

    # Sharing the same entry with the same person twice is rejected
    def test_duplicate_entry_share_fails(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_user(db_connection, "jon")
        amy = make_user(db_connection, "amy")
        vault = make_vault(db_connection, jon)
        entry = make_entry(db_connection, vault, jon)
        storage.create_entry_share(db_connection, entry, amy, os.urandom(92))

        with pytest.raises(sqlite3.IntegrityError):
            storage.create_entry_share(db_connection, entry, amy, os.urandom(92))
        db_connection.close()