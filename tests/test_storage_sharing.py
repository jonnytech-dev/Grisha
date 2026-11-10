from core import storage
import os
import pytest
import uuid


# ========== Setup helpers ==========

def setup_db(tmp_path):
    # Fresh DB with tables for each test
    db_connection = storage.db_connect(tmp_path / "test.db")
    storage.create_tables(db_connection)
    return db_connection


def add_user(db_connection, username):
    # Inserts a test user with fake keys and returns their user_id
    user_id = str(uuid.uuid4())
    db_connection.execute(
        """INSERT INTO users (user_id, username, email, password_hash, encrypted_dek, encrypted_dek_nonce,
                              kek_salt, public_key, encrypted_private_key, private_key_nonce)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (user_id, username, f"{username}@example.com", "$argon2id$fake", os.urandom(48), os.urandom(12),
         os.urandom(16), os.urandom(32), os.urandom(48), os.urandom(12)),
    )
    return user_id


def add_vault(db_connection, owner_id, member_role="view"):
    # Inserts a vault and gives the owner a share row, returns the vault_id
    vault_id = str(uuid.uuid4())
    db_connection.execute(
        "INSERT INTO vaults (vault_id, vault_name, owner_id, member_role) VALUES (?, ?, ?, ?)",
        (vault_id, "Test Vault", owner_id, member_role),
    )
    add_vault_member(db_connection, vault_id, owner_id)
    return vault_id


def add_vault_member(db_connection, vault_id, user_id, role=None, wrapped_vault_key=None):
    # Adds a user to a vault, role None means "use the vault's member_role"
    db_connection.execute(
        "INSERT INTO vault_shares (vault_id, user_id, wrapped_vault_key, role) VALUES (?, ?, ?, ?)",
        (vault_id, user_id, wrapped_vault_key or os.urandom(92), role),
    )


def add_entry(db_connection, vault_id, created_by, wrapped_entry_key=None):
    # Inserts an entry into a vault, returns the vault_entry_id
    vault_entry_id = str(uuid.uuid4())
    db_connection.execute(
        """INSERT INTO vault_entries (vault_entry_id, vault_id, created_by, wrapped_entry_key,
                                      entry_key_nonce, nonce, ciphertext)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (vault_entry_id, vault_id, created_by, wrapped_entry_key or os.urandom(48),
         os.urandom(12), os.urandom(12), os.urandom(60)),
    )
    return vault_entry_id


def add_direct_share(db_connection, vault_entry_id, user_id, role="view", wrapped_entry_key=None):
    # Shares one entry directly with a user
    db_connection.execute(
        "INSERT INTO entry_shares (vault_entry_id, user_id, wrapped_entry_key, role) VALUES (?, ?, ?, ?)",
        (vault_entry_id, user_id, wrapped_entry_key or os.urandom(92), role),
    )


# ========== Vault path: get_vault_entries ==========

class Test_Get_Vault_Entries:
    # A member sees every entry in the vault, including ones other members created
    def test_member_sees_entries_others_created(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = add_user(db_connection, "jon")
        brock = add_user(db_connection, "brock")
        work = add_vault(db_connection, jon)
        add_vault_member(db_connection, work, brock)

        aws = add_entry(db_connection, work, created_by=jon)
        github = add_entry(db_connection, work, created_by=brock)

        ids = [row["vault_entry_id"] for row in storage.get_vault_entries(db_connection, brock)]
        assert len(ids) == 2
        assert aws in ids
        assert github in ids
        db_connection.close()

    # Entries in vaults the user isn't in never come back
    def test_only_entries_from_own_vaults(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = add_user(db_connection, "jon")
        brock = add_user(db_connection, "brock")
        work = add_vault(db_connection, jon)
        personal = add_vault(db_connection, jon)
        add_vault_member(db_connection, work, brock)

        work_entry = add_entry(db_connection, work, created_by=jon)
        personal_entry = add_entry(db_connection, personal, created_by=jon)

        ids = [row["vault_entry_id"] for row in storage.get_vault_entries(db_connection, brock)]
        assert work_entry in ids
        assert personal_entry not in ids
        db_connection.close()

    # Each entry comes back once, not once per vault member
    def test_no_duplicate_rows(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = add_user(db_connection, "jon")
        brock = add_user(db_connection, "brock")
        amy = add_user(db_connection, "amy")
        work = add_vault(db_connection, jon)
        add_vault_member(db_connection, work, brock)
        add_vault_member(db_connection, work, amy)
        add_entry(db_connection, work, created_by=jon)

        assert len(storage.get_vault_entries(db_connection, brock)) == 1
        db_connection.close()

    # A user in no vaults gets an empty list
    def test_no_vaults_returns_empty(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = add_user(db_connection, "jon")
        eve = add_user(db_connection, "eve")
        work = add_vault(db_connection, jon)
        add_entry(db_connection, work, created_by=jon)

        assert storage.get_vault_entries(db_connection, eve) == []
        db_connection.close()


# ========== Vault path: get_vault_entry ==========

class Test_Get_Vault_Entry:
    # A member gets the entry, with THEIR OWN wrapped vault key
    def test_returns_members_own_wrapped_vault_key(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = add_user(db_connection, "jon")
        brock = add_user(db_connection, "brock")
        work = add_vault(db_connection, jon)
        brocks_copy = os.urandom(92)
        add_vault_member(db_connection, work, brock, wrapped_vault_key=brocks_copy)
        entry = add_entry(db_connection, work, created_by=jon)

        row = storage.get_vault_entry(db_connection, brock, entry)
        assert row["wrapped_vault_key"] == brocks_copy
        db_connection.close()

    # A non-member gets None, even with the entry id
    def test_non_member_gets_none(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = add_user(db_connection, "jon")
        eve = add_user(db_connection, "eve")
        work = add_vault(db_connection, jon)
        entry = add_entry(db_connection, work, created_by=jon)

        assert storage.get_vault_entry(db_connection, eve, entry) is None
        db_connection.close()

    # A missing entry id returns None
    def test_missing_entry_returns_none(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = add_user(db_connection, "jon")
        add_vault(db_connection, jon)

        assert storage.get_vault_entry(db_connection, jon, str(uuid.uuid4())) is None
        db_connection.close()

    # No override → the vault's member_role is used
    def test_role_falls_back_to_vault_default(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = add_user(db_connection, "jon")
        brock = add_user(db_connection, "brock")
        work = add_vault(db_connection, jon, member_role="view")
        add_vault_member(db_connection, work, brock, role=None)
        entry = add_entry(db_connection, work, created_by=jon)

        assert storage.get_vault_entry(db_connection, brock, entry)["role"] == "view"
        db_connection.close()

    # A member's own role overrides the vault's default
    def test_member_role_overrides_vault_default(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = add_user(db_connection, "jon")
        kim = add_user(db_connection, "kim")
        work = add_vault(db_connection, jon, member_role="view")
        add_vault_member(db_connection, work, kim, role="edit")
        entry = add_entry(db_connection, work, created_by=jon)

        assert storage.get_vault_entry(db_connection, kim, entry)["role"] == "edit"
        db_connection.close()

    # owner_id comes back so vault.py can give the owner full rights
    def test_returns_owner_id(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = add_user(db_connection, "jon")
        brock = add_user(db_connection, "brock")
        work = add_vault(db_connection, jon)
        add_vault_member(db_connection, work, brock)
        entry = add_entry(db_connection, work, created_by=brock)

        assert storage.get_vault_entry(db_connection, brock, entry)["owner_id"] == jon
        db_connection.close()


# ========== Direct path: get_shared_entry ==========

class Test_Get_Shared_Entry:
    # A direct share returns the user's own wrapped entry key, not the vault's
    def test_returns_users_own_wrapped_entry_key(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = add_user(db_connection, "jon")
        amy = add_user(db_connection, "amy")
        work = add_vault(db_connection, jon)
        vaults_copy = os.urandom(48)
        amys_copy = os.urandom(92)
        entry = add_entry(db_connection, work, created_by=jon, wrapped_entry_key=vaults_copy)
        add_direct_share(db_connection, entry, amy, wrapped_entry_key=amys_copy)

        row = storage.get_shared_entry(db_connection, amy, entry)
        assert row["wrapped_entry_key"] == amys_copy
        assert row["wrapped_entry_key"] != vaults_copy
        db_connection.close()

    # The direct share's role comes back
    def test_returns_share_role(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = add_user(db_connection, "jon")
        amy = add_user(db_connection, "amy")
        work = add_vault(db_connection, jon)
        entry = add_entry(db_connection, work, created_by=jon)
        add_direct_share(db_connection, entry, amy, role="edit")

        assert storage.get_shared_entry(db_connection, amy, entry)["role"] == "edit"
        db_connection.close()

    # No direct share → None
    def test_not_shared_returns_none(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = add_user(db_connection, "jon")
        eve = add_user(db_connection, "eve")
        work = add_vault(db_connection, jon)
        entry = add_entry(db_connection, work, created_by=jon)

        assert storage.get_shared_entry(db_connection, eve, entry) is None
        db_connection.close()

    # A vault member with no direct share gets None from the DIRECT path
    def test_vault_member_not_on_direct_path(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = add_user(db_connection, "jon")
        brock = add_user(db_connection, "brock")
        work = add_vault(db_connection, jon)
        add_vault_member(db_connection, work, brock)
        entry = add_entry(db_connection, work, created_by=jon)

        assert storage.get_shared_entry(db_connection, brock, entry) is None
        db_connection.close()


# ========== Direct path: get_shared_entries ==========

class Test_Get_Shared_Entries:
    # Only the entries shared directly come back, not the rest of the vault
    def test_only_shared_entries(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = add_user(db_connection, "jon")
        amy = add_user(db_connection, "amy")
        work = add_vault(db_connection, jon)
        wifi = add_entry(db_connection, work, created_by=jon)
        aws = add_entry(db_connection, work, created_by=jon)
        add_direct_share(db_connection, wifi, amy)

        ids = [row["vault_entry_id"] for row in storage.get_shared_entries(db_connection, amy)]
        assert ids == [wifi]
        assert aws not in ids
        db_connection.close()

    # Multiple direct shares all come back
    def test_multiple_shares(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = add_user(db_connection, "jon")
        amy = add_user(db_connection, "amy")
        work = add_vault(db_connection, jon)
        wifi = add_entry(db_connection, work, created_by=jon)
        aws = add_entry(db_connection, work, created_by=jon)
        add_direct_share(db_connection, wifi, amy)
        add_direct_share(db_connection, aws, amy)

        ids = [row["vault_entry_id"] for row in storage.get_shared_entries(db_connection, amy)]
        assert len(ids) == 2
        assert wifi in ids
        assert aws in ids
        db_connection.close()

    # Nothing shared → empty list
    def test_nothing_shared_returns_empty(self, tmp_path):
        db_connection = setup_db(tmp_path)
        amy = add_user(db_connection, "amy")

        assert storage.get_shared_entries(db_connection, amy) == []
        db_connection.close()