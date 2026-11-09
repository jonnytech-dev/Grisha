from core import auth, storage, vault
import pytest
import uuid
from cryptography.exceptions import InvalidTag


PASSWORD = "c0rrect1horseb@ttery"


def setup_db(tmp_path):
    # Fresh DB with tables for each test
    db_connection = storage.db_connect(tmp_path / "test.db")
    storage.create_tables(db_connection)
    return db_connection


def make_session(db_connection, username, email):
    # Registers a user and logs them in, returning their Session
    auth.register(db_connection, username, email, PASSWORD)
    return auth.login(db_connection, email, PASSWORD)


def add_gmail(db_connection, session):
    # Adds a standard test entry and returns its id
    return vault.add_entry(db_connection, session, "Gmail", "https://mail.google.com",
                           "jon@gmail.com", "SneakyPanda!22", "recovery code 1234")


# ========== Add and Get ==========

class Test_Add_And_Get:
    # Every field saved comes back exactly the same
    def test_add_then_get_returns_same_fields(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon", "jon@gmail.com")

        vault_entry_id = add_gmail(db_connection, jon)
        entry = vault.get_entry(db_connection, jon, vault_entry_id)

        assert entry.vault_entry_id == vault_entry_id
        assert entry.title == "Gmail"
        assert entry.url == "https://mail.google.com"
        assert entry.username == "jon@gmail.com"
        assert entry.password == "SneakyPanda!22"
        assert entry.notes == "recovery code 1234"
        db_connection.close()

    # An entry with no title is rejected
    def test_empty_title_fails(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon", "jon@gmail.com")

        with pytest.raises(ValueError):
            vault.add_entry(db_connection, jon, "", "", "", "pw", "")
        db_connection.close()

    # An id that doesn't exist returns None
    def test_get_missing_entry_returns_none(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon", "jon@gmail.com")

        assert vault.get_entry(db_connection, jon, str(uuid.uuid4())) is None
        db_connection.close()


# ========== Encryption at Rest ==========

class Test_Encryption_At_Rest:
    # Nothing readable may appear in the stored ciphertext
    def test_database_holds_no_plaintext(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon", "jon@gmail.com")
        add_gmail(db_connection, jon)

        row = db_connection.execute("SELECT ciphertext FROM vault_entries").fetchone()
        assert b"SneakyPanda!22" not in row["ciphertext"]
        assert b"Gmail" not in row["ciphertext"]
        assert b"recovery code" not in row["ciphertext"]
        db_connection.close()

    # Swapping two of Jon's ciphertexts must be caught by the per-entry AAD
    def test_swapped_entries_fail(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon", "jon@gmail.com")
        entry_a = add_gmail(db_connection, jon)
        entry_b = vault.add_entry(db_connection, jon, "Bank", "", "jon", "BankPw!99", "")

        row_a = db_connection.execute("SELECT nonce, ciphertext FROM vault_entries WHERE vault_entry_id = ?", (entry_a,)).fetchone()
        row_b = db_connection.execute("SELECT nonce, ciphertext FROM vault_entries WHERE vault_entry_id = ?", (entry_b,)).fetchone()
        db_connection.execute("UPDATE vault_entries SET nonce = ?, ciphertext = ? WHERE vault_entry_id = ?", (row_b["nonce"], row_b["ciphertext"], entry_a))
        db_connection.execute("UPDATE vault_entries SET nonce = ?, ciphertext = ? WHERE vault_entry_id = ?", (row_a["nonce"], row_a["ciphertext"], entry_b))
        db_connection.commit()

        with pytest.raises(InvalidTag):
            vault.get_entry(db_connection, jon, entry_a)
        db_connection.close()


# ========== List ==========

class Test_List:
    # A new user has an empty vault
    def test_list_empty(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon", "jon@gmail.com")

        assert vault.list_entries(db_connection, jon) == []
        db_connection.close()

    # Every entry comes back decrypted
    def test_list_returns_all_entries(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon", "jon@gmail.com")
        add_gmail(db_connection, jon)
        vault.add_entry(db_connection, jon, "Bank", "", "jon", "BankPw!99", "")

        titles = [entry.title for entry in vault.list_entries(db_connection, jon)]
        assert len(titles) == 2
        assert "Gmail" in titles
        assert "Bank" in titles
        db_connection.close()


# ========== Update ==========

class Test_Update:
    # Updating changes the fields
    def test_update_changes_fields(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon", "jon@gmail.com")
        vault_entry_id = add_gmail(db_connection, jon)

        assert vault.update_entry(db_connection, jon, vault_entry_id, "Gmail", "", "jon@gmail.com", "NewPass!33", "") is True
        assert vault.get_entry(db_connection, jon, vault_entry_id).password == "NewPass!33"
        db_connection.close()

    # Every update must use a new nonce
    def test_update_uses_new_nonce(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon", "jon@gmail.com")
        vault_entry_id = add_gmail(db_connection, jon)
        before = db_connection.execute("SELECT nonce FROM vault_entries").fetchone()["nonce"]

        vault.update_entry(db_connection, jon, vault_entry_id, "Gmail", "", "jon@gmail.com", "SneakyPanda!22", "")

        after = db_connection.execute("SELECT nonce FROM vault_entries").fetchone()["nonce"]
        assert before != after
        db_connection.close()


# ========== Delete ==========

class Test_Delete:
    # Deleting removes the entry
    def test_delete_entry(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon", "jon@gmail.com")
        vault_entry_id = add_gmail(db_connection, jon)

        assert vault.delete_entry(db_connection, jon, vault_entry_id) is True
        assert vault.get_entry(db_connection, jon, vault_entry_id) is None
        db_connection.close()


# ========== Other Users ==========

class Test_Other_Users:
    # Brock can't read, edit, or delete Jon's entry, even with its id
    def test_other_user_cannot_touch_entry(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon", "jon@gmail.com")
        brock = make_session(db_connection, "brock", "brock@gmail.com")
        jon_entry = add_gmail(db_connection, jon)

        assert vault.get_entry(db_connection, brock, jon_entry) is None
        assert vault.update_entry(db_connection, brock, jon_entry, "Hacked", "", "", "", "") is False
        assert vault.delete_entry(db_connection, brock, jon_entry) is False

        # Jon's entry is untouched
        assert vault.get_entry(db_connection, jon, jon_entry).title == "Gmail"
        db_connection.close()

    # Brock's list never includes Jon's entries
    def test_list_only_shows_own(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon", "jon@gmail.com")
        brock = make_session(db_connection, "brock", "brock@gmail.com")
        add_gmail(db_connection, jon)

        assert vault.list_entries(db_connection, brock) == []
        db_connection.close()