from core import storage
import sqlite3
from pathlib import Path
import os
import pytest
import uuid

# python -m pytest -v -s 

# ========== DB Connection ==========

class Test_DB_Connection:
    # Open and close the db connection
    def test_db_open_close_connection(self, tmp_path):
        # Test db file path
        # tmp_path is a new empty folder pytest creates for each test, so every test starts with a fresh DB
        path = tmp_path / "test.db"

        # Start the connection to a test.db file
        db_connection = storage.db_connect(path)

        # Test if connection is axtually open
        assert isinstance(db_connection, sqlite3.Connection)
        
        # Test if db file exist
        assert path.exists()
        assert db_connection.execute("SELECT 1").fetchone()[0] == 1  # simplest possible query, returns 1
        assert db_connection.row_factory is sqlite3.Row          # row_factory set?

        # Close the connection
        db_connection.close()

        # Test if connection is actually closed
        # Using a closed connection must raise ProgrammingError
        assert isinstance(db_connection, sqlite3.Connection)
        with pytest.raises(sqlite3.ProgrammingError):
            assert db_connection.execute("SELECT username FROM users").fetchone()[0]


# ========== DB Tables ==========

class Test_DB_Tables:
    # Test if create_tables actually created the users tables by inserting a test user
    def test_db_create_user_table(self, tmp_path):
        # Test db file path
        path = tmp_path / "test.db"

        # Start the connection to a test.db file
        db_connection = storage.db_connect(path)
        # Run the creat tables function
        storage.create_tables(db_connection)

        # Test users data
        user_id = str(uuid.uuid4())

        user_data = [
            (
                user_id,
                "jon",                  # username
                "jon@example.com",      # email
                "$argon2id$fake",       # password_hash
                "user",                 # role
                os.urandom(48),         # encrypted_dek
                os.urandom(12),         # encrypted_dek_nonce
                os.urandom(16),         # kek_salt)
            )
        ]
        # Insert the data into the table
        # Values match the column list by position, so the tuple order must match the columns
        db_connection.execute("INSERT INTO users (user_id, username, email, password_hash, role, encrypted_dek, encrypted_dek_nonce, kek_salt) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", user_data[0])

        # Test if attributes with the test user Jon exist
        test_username = db_connection.execute("SELECT username FROM users").fetchone()
        assert test_username["username"] == "jon"

        # Close the connection
        db_connection.execute("DELETE FROM users")
        db_connection.close()

    # Test if create_tables actually created the vault_entries tables by inserting a test user and test entry
    def test_db_create_vault_entries_table(self, tmp_path):
        # Test db file path
        path = tmp_path / "test.db"

        # Start the connection to a test.db file
        db_connection = storage.db_connect(path)
        # Run the creat tables function
        storage.create_tables(db_connection)

        # Test users data
        user_id = str(uuid.uuid4())
      
        user_data = [
            (
                user_id,
                "jon",                  # username
                "jon@example.com",      # email
                "$argon2id$fake",       # password_hash
                "user",                 # role
                os.urandom(48),         # encrypted_dek
                os.urandom(12),         # encrypted_dek_nonce
                os.urandom(16),         # kek_salt)
            )
        ]
        # Test vault_entries data
        vault_entry_id = str(uuid.uuid4())

        entry_data = [
            (
                vault_entry_id,
                user_id,                # user's uuid, foreign key to users id
                os.urandom(12),         # nonce
                os.urandom(40),         # ciphertext
            )
        ]

        # Insert the data into the table
        # The user must be inserted first. The entry's user_id must point to a real user, or the foreign key rejects it.
        db_connection.execute("INSERT INTO users (user_id, username, email, password_hash, role, encrypted_dek, encrypted_dek_nonce, kek_salt) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", user_data[0])
        db_connection.execute("INSERT INTO vault_entries (vault_entry_id, user_id, nonce, ciphertext) VALUES (?, ?, ?, ?)", entry_data[0])

        # Test if attributes with the test user Jon exist
        test_entry = db_connection.execute("SELECT user_id FROM vault_entries").fetchone()
        assert test_entry["user_id"] == user_id

        db_connection.execute("DELETE FROM users")
        db_connection.close()

    # Test if create_tables actually creates the core tables (users, vault_entries)
    def test_db_create_tables(self, tmp_path):
        # Test db file path
        path = tmp_path / "test.db"

        # Start the connection to a test.db file
        db_connection = storage.db_connect(path)

        # Run the creat tables function
        storage.create_tables(db_connection)

        # Test if tables exist
        # sqlite_master is SQLite's built-in list of every table in the DB
        # Running these queries after create_tables also proves create_tables left the connection open
        tables = db_connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        table_names = [table["name"] for table in tables]
        assert "users" in table_names
        assert "vault_entries" in table_names

        # Close the connection
        db_connection.execute("DELETE FROM users")
        db_connection.close()


# ========== Users ==========

class Test_Users:
    # Test creating a new user
    def test_create_new_user(self, tmp_path):
        db_connection = storage.db_connect(tmp_path / "test.db")
        storage.create_tables(db_connection)
        
        user_id_1 = str(uuid.uuid4())
        storage.create_user(
            db_connection,
            user_id=user_id_1,
            username="jonny",
            email="jonny@gmail.com",
            password_hash="$argon2id$fake",
            encrypted_dek=os.urandom(48),
            encrypted_dek_nonce=os.urandom(12),
            kek_salt=os.urandom(16),
        )

        user_id_2 = str(uuid.uuid4())
        storage.create_user(
            db_connection,
            user_id=user_id_2,
            username="gavin",
            email="gavin@example.com",
            password_hash="$argon2id$fake",
            encrypted_dek=os.urandom(48),
            encrypted_dek_nonce=os.urandom(12),
            kek_salt=os.urandom(16),
        )

        # Users in the db must match those just created
        # Checks with "in" instead of position, since SQL does not guarantee row order
        rows = db_connection.execute("SELECT user_id FROM users").fetchall()
        users = [row["user_id"] for row in rows]
        assert len(rows) == 2
        assert user_id_1 in users
        assert user_id_2 in users

        db_connection.execute("DELETE FROM users")
        db_connection.close()

    # Test creating a user with a already existing email
    def test_create_duplicate_user_email(self, tmp_path):
        # Only the email is the same. The username is different, so the only reason this can fail is the duplicate email.
        db_connection = storage.db_connect(tmp_path / "test.db")
        storage.create_tables(db_connection)
        
        storage.create_user(
            db_connection,
            user_id=str(uuid.uuid4()),
            username="jonny",
            email="jonny@gmail.com",
            password_hash="$argon2id$fake",
            encrypted_dek=os.urandom(48),
            encrypted_dek_nonce=os.urandom(12),
            kek_salt=os.urandom(16),
        )

        with pytest.raises(sqlite3.IntegrityError):
            storage.create_user(
                db_connection,
                user_id=str(uuid.uuid4()),
                username="gavin",
                email="jonny@gmail.com",
                password_hash="$argon2id$fake",
                encrypted_dek=os.urandom(48),
                encrypted_dek_nonce=os.urandom(12),
                kek_salt=os.urandom(16),
            )

        db_connection.execute("DELETE FROM users")
        db_connection.close()

    # Test creating a user with a already existing username
    def test_create_duplicate_user_username(self, tmp_path):
        # Only the username is the same. The email is different, so the only reason this can fail is the duplicate username.
        db_connection = storage.db_connect(tmp_path / "test.db")
        storage.create_tables(db_connection)
        
        storage.create_user(
            db_connection,
            user_id=str(uuid.uuid4()),
            username="jonny",
            email="jonny@gmail.com",
            password_hash="$argon2id$fake",
            encrypted_dek=os.urandom(48),
            encrypted_dek_nonce=os.urandom(12),
            kek_salt=os.urandom(16),
        )

        with pytest.raises(sqlite3.IntegrityError):
            storage.create_user(
                db_connection,
                user_id=str(uuid.uuid4()),
                username="jonny",
                email="gavin@gmail.com",
                password_hash="$argon2id$fake",
                encrypted_dek=os.urandom(48),
                encrypted_dek_nonce=os.urandom(12),
                kek_salt=os.urandom(16),
            )

        db_connection.execute("DELETE FROM users")
        db_connection.close()

    # Test finding a user by email
    def test_find_user_by_email(self, tmp_path):
        db_connection = storage.db_connect(tmp_path / "test.db")
        storage.create_tables(db_connection)
        
        user_id_1 = str(uuid.uuid4())
        storage.create_user(
            db_connection,
            user_id=user_id_1,
            username="jonny",
            email="jonny@gmail.com",
            password_hash="$argon2id$fake",
            encrypted_dek=os.urandom(48),
            encrypted_dek_nonce=os.urandom(12),
            kek_salt=os.urandom(16),
        )

        user_id_2 = str(uuid.uuid4())
        storage.create_user(
            db_connection,
            user_id=user_id_2,
            username="gavin",
            email="gavin@example.com",
            password_hash="$argon2id$fakedsdasdasdasd",
            encrypted_dek=os.urandom(48),
            encrypted_dek_nonce=os.urandom(12),
            kek_salt=os.urandom(16),
        )

        email = "jonny@gmail.com"
        user_data = storage.get_user_by_email(db_connection, email)
        assert user_data["password_hash"] == "$argon2id$fake"

        db_connection.close()

    # Test finding a user by email that doesn't exist
    def test_find_nonexisiting_user_by_email(self, tmp_path):
        db_connection = storage.db_connect(tmp_path / "test.db")
        storage.create_tables(db_connection)
        
        user_id_1 = str(uuid.uuid4())
        storage.create_user(
            db_connection,
            user_id=user_id_1,
            username="jonny",
            email="jonny@gmail.com",
            password_hash="$argon2id$fake",
            encrypted_dek=os.urandom(48),
            encrypted_dek_nonce=os.urandom(12),
            kek_salt=os.urandom(16),
        )

        user_id_2 = str(uuid.uuid4())
        storage.create_user(
            db_connection,
            user_id=user_id_2,
            username="gavin",
            email="gavin@example.com",
            password_hash="$argon2id$fake",
            encrypted_dek=os.urandom(48),
            encrypted_dek_nonce=os.urandom(12),
            kek_salt=os.urandom(16),
        )

        email = "blue_dolphin@gmail.com"
        assert storage.get_user_by_email(db_connection, email) is None

        db_connection.close()

    # Test that an email saved with capitals can be found with lowercase
    def test_get_user_by_email_saved_with_capitals(self, tmp_path):
        # create_user saves emails as lowercase, so "Jonny@Gmail.com" is stored as "jonny@gmail.com"
        db_connection = storage.db_connect(tmp_path / "test.db")
        storage.create_tables(db_connection)

        user_id = str(uuid.uuid4())
        storage.create_user(
            db_connection,
            user_id=user_id,
            username="jonny",
            email="Jonny@Gmail.com",
            password_hash="$argon2id$fake",
            encrypted_dek=os.urandom(48),
            encrypted_dek_nonce=os.urandom(12),
            kek_salt=os.urandom(16),
        )

        user_data = storage.get_user_by_email(db_connection, "jonny@gmail.com")
        assert user_data is not None
        assert user_data["user_id"] == user_id

        db_connection.close()

    # Test that an email can be found when searched with capitals
    def test_get_user_by_email_searched_with_capitals(self, tmp_path):
        # get_user_by_email lowercases the search, so "JONNY@GMAIL.COM" still finds "jonny@gmail.com"
        db_connection = storage.db_connect(tmp_path / "test.db")
        storage.create_tables(db_connection)

        user_id = str(uuid.uuid4())
        storage.create_user(
            db_connection,
            user_id=user_id,
            username="jonny",
            email="jonny@gmail.com",
            password_hash="$argon2id$fake",
            encrypted_dek=os.urandom(48),
            encrypted_dek_nonce=os.urandom(12),
            kek_salt=os.urandom(16),
        )

        user_data = storage.get_user_by_email(db_connection, "JONNY@GMAIL.COM")
        assert user_data is not None
        assert user_data["user_id"] == user_id

        db_connection.close()

    # Test that the same email with different capitals counts as a duplicate
    def test_duplicate_email_different_capitals(self, tmp_path):
        # Both emails become "jonny@gmail.com" when saved, so UNIQUE must reject the second one.
        # Without lowercasing, these would be two accounts for the same real email.
        db_connection = storage.db_connect(tmp_path / "test.db")
        storage.create_tables(db_connection)

        storage.create_user(
            db_connection,
            user_id=str(uuid.uuid4()),
            username="jonny",
            email="jonny@gmail.com",
            password_hash="$argon2id$fake",
            encrypted_dek=os.urandom(48),
            encrypted_dek_nonce=os.urandom(12),
            kek_salt=os.urandom(16),
        )

        with pytest.raises(sqlite3.IntegrityError):
            storage.create_user(
                db_connection,
                user_id=str(uuid.uuid4()),
                username="gavin",
                email="Jonny@Gmail.com",
                password_hash="$argon2id$fake",
                encrypted_dek=os.urandom(48),
                encrypted_dek_nonce=os.urandom(12),
                kek_salt=os.urandom(16),
            )

        db_connection.close()

# ========== SQL Injection ==========

class Test_SQL_Injection:
    def test_insert_injection_is_stored_as_plain_text(self, tmp_path):
        # A malicious username must be saved as plain text, not run as SQL.
        # If create_user ever builds SQL with an f-string, this test fails.
        db_connection = storage.db_connect(tmp_path / "test.db")
        storage.create_tables(db_connection)

        # Tries to close the INSERT early, drop the users table, and comment out the rest
        payload = "jon'); DROP TABLE users; --"
        
        storage.create_user(
            db_connection,
            user_id=str(uuid.uuid4()),
            username=payload,
            email="jon@example.com",
            password_hash="$argon2id$fake",
            encrypted_dek=os.urandom(48),
            encrypted_dek_nonce=os.urandom(12),
            kek_salt=os.urandom(16),
        )

        # The users table must still exist
        tables = db_connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        assert "users" in [table["name"] for table in tables]

        # Exactly one user, stored with the payload as its literal username
        rows = db_connection.execute("SELECT username, role FROM users").fetchall()
        assert len(rows) == 1
        assert rows[0]["username"] == payload

        # The injection must not change other columns
        assert rows[0]["role"] == "user"

        db_connection.execute("DELETE FROM users")
        db_connection.close()

def make_user(db_connection, username, email):
    # Creates a test user and returns their user_id
    user_id = str(uuid.uuid4())
    storage.create_user(
        db_connection,
        user_id=user_id,
        username=username,
        email=email,
        password_hash="$argon2id$fake",
        encrypted_dek=os.urandom(48),
        encrypted_dek_nonce=os.urandom(12),
        kek_salt=os.urandom(16),
    )
    return user_id

class Test_Vault_Entries:
    # Saved nonce and ciphertext must come back exactly the same
    def test_create_and_get_entry(self, tmp_path):
        db_connection = storage.db_connect(tmp_path / "test.db")
        storage.create_tables(db_connection)
        jon = make_user(db_connection, "jon", "jon@example.com")

        nonce = os.urandom(12)
        ciphertext = os.urandom(40)

        vault_entry_id = str(uuid.uuid4())
        storage.create_vault_entry(db_connection, vault_entry_id, jon, nonce, ciphertext)

        entry = storage.get_vault_entry(db_connection, jon, vault_entry_id)
        assert entry["nonce"] == nonce
        assert entry["ciphertext"] == ciphertext
        db_connection.close()

    # A user with no entries gets an empty list, not None
    def test_get_entries_empty(self, tmp_path):
        db_connection = storage.db_connect(tmp_path / "test.db")
        storage.create_tables(db_connection)
        jon = make_user(db_connection, "jon", "jon@example.com")

        assert storage.get_vault_entries(db_connection, jon) == []
        db_connection.close()

    # get_vault_entries returns only the asking user's entries
    def test_get_entries_only_returns_own(self, tmp_path):
        db_connection = storage.db_connect(tmp_path / "test.db")
        storage.create_tables(db_connection)
        jon = make_user(db_connection, "jon", "jon@example.com")
        brock = make_user(db_connection, "brock", "brock@example.com")

        jon_entry_1 = str(uuid.uuid4())
        jon_entry_2 = str(uuid.uuid4())
        brock_entry = str(uuid.uuid4())
        storage.create_vault_entry(db_connection, jon_entry_1, jon, os.urandom(12), os.urandom(40))
        storage.create_vault_entry(db_connection, jon_entry_2, jon, os.urandom(12), os.urandom(40))
        storage.create_vault_entry(db_connection, brock_entry, brock, os.urandom(12), os.urandom(40))

        ids = [row["vault_entry_id"] for row in storage.get_vault_entries(db_connection, jon)]
        assert len(ids) == 2
        assert jon_entry_1 in ids
        assert jon_entry_2 in ids
        assert brock_entry not in ids
        db_connection.close()

    # An id that doesn't exist returns None
    def test_get_missing_entry_returns_none(self, tmp_path):
        db_connection = storage.db_connect(tmp_path / "test.db")
        storage.create_tables(db_connection)
        jon = make_user(db_connection, "jon", "jon@example.com")

        assert storage.get_vault_entry(db_connection, jon, str(uuid.uuid4())) is None
        db_connection.close()

    # Updating changes the stored values and returns True
    def test_update_own_entry(self, tmp_path):
        db_connection = storage.db_connect(tmp_path / "test.db")
        storage.create_tables(db_connection)
        jon = make_user(db_connection, "jon", "jon@example.com")
        vault_entry_id = str(uuid.uuid4())
        storage.create_vault_entry(db_connection, vault_entry_id, jon, os.urandom(12), os.urandom(40))

        new_nonce = os.urandom(12)
        new_ciphertext = os.urandom(40)
        assert storage.update_vault_entry(db_connection, jon, vault_entry_id, new_nonce, new_ciphertext) is True

        entry = storage.get_vault_entry(db_connection, jon, vault_entry_id)
        assert entry["nonce"] == new_nonce
        assert entry["ciphertext"] == new_ciphertext
        db_connection.close()

    # Updating no changes to the stored values and returns False
    # def test_update_own_entry_no_change(self, tmp_path):
    #     db_connection = storage.db_connect(tmp_path / "test.db")
    #     storage.create_tables(db_connection)
    #     jon = make_user(db_connection, "jon", "jon@example.com")
    #     nonce = os.urandom(12)
    #     ciphertext = os.urandom(40)
    #     vault_entry_id = storage.create_vault_entry(db_connection, jon, nonce, ciphertext)

    #     assert storage.update_vault_entry(db_connection, jon, vault_entry_id, nonce, ciphertext) is False

    #     entry = storage.get_vault_entry(db_connection, jon, vault_entry_id)
    #     assert entry["nonce"] == nonce
    #     assert entry["ciphertext"] == ciphertext
    #     db_connection.close()

    # Deleting removes the entry and returns True
    def test_delete_own_entry(self, tmp_path):
        db_connection = storage.db_connect(tmp_path / "test.db")
        storage.create_tables(db_connection)
        jon = make_user(db_connection, "jon", "jon@example.com")
        vault_entry_id = str(uuid.uuid4())
        storage.create_vault_entry(db_connection, vault_entry_id, jon, os.urandom(12), os.urandom(40))

        assert storage.delete_vault_entry(db_connection, jon, vault_entry_id) is True
        assert storage.get_vault_entry(db_connection, jon, vault_entry_id) is None
        db_connection.close()

    # Delete entry for an existing user but non existent entry
    def test_delete_non_existent_entry(self, tmp_path):
        db_connection = storage.db_connect(tmp_path / "test.db")
        storage.create_tables(db_connection)
        jon = make_user(db_connection, "jon", "jon@example.com")
        vault_entry_id = str(uuid.uuid4())

        assert storage.delete_vault_entry(db_connection, jon, vault_entry_id) is False
        db_connection.close()

    # Delete entry for non existent user and non existent entry
    def test_delete_entry_by_non_existent_user(self, tmp_path):
        db_connection = storage.db_connect(tmp_path / "test.db")
        storage.create_tables(db_connection)
        jon = str(uuid.uuid4())
        vault_entry_id = str(uuid.uuid4())

        assert storage.delete_vault_entry(db_connection, jon, vault_entry_id) is False
        db_connection.close()

# ========== IDOR (accessing another user's entries) ==========

class Test_IDOR:
    # Jon knows Brock's entry id. He still must not be able to read it.
    def test_cannot_get_other_users_entry(self, tmp_path):
        db_connection = storage.db_connect(tmp_path / "test.db")
        storage.create_tables(db_connection)
        jon = make_user(db_connection, "jon", "jon@example.com")
        brock = make_user(db_connection, "brock", "brock@example.com")
        brock_entry = str(uuid.uuid4())
        storage.create_vault_entry(db_connection, brock_entry, brock, os.urandom(12), os.urandom(40))

        assert storage.get_vault_entry(db_connection, jon, brock_entry) is None
        db_connection.close()

    # Jon must not be able to overwrite Brock's entry, and Brock's data must stay unchanged
    def test_cannot_update_other_users_entry(self, tmp_path):
        db_connection = storage.db_connect(tmp_path / "test.db")
        storage.create_tables(db_connection)
        jon = make_user(db_connection, "jon", "jon@example.com")
        brock = make_user(db_connection, "brock", "brock@example.com")
        brock_entry = str(uuid.uuid4())
        storage.create_vault_entry(db_connection, brock_entry, brock, os.urandom(12), os.urandom(40))
        before = storage.get_vault_entry(db_connection, brock, brock_entry)["ciphertext"]

        assert storage.update_vault_entry(db_connection, jon, brock_entry, os.urandom(12), os.urandom(40)) is False

        after = storage.get_vault_entry(db_connection, brock, brock_entry)["ciphertext"]
        assert after == before
        db_connection.close()

    # Jon must not be able to delete Brock's entry, and it must still exist after
    def test_cannot_delete_other_users_entry(self, tmp_path):
        db_connection = storage.db_connect(tmp_path / "test.db")
        storage.create_tables(db_connection)
        jon = make_user(db_connection, "jon", "jon@example.com")
        brock = make_user(db_connection, "brock", "brock@example.com")
        brock_entry = str(uuid.uuid4())
        storage.create_vault_entry(db_connection, brock_entry, brock, os.urandom(12), os.urandom(40))

        assert storage.delete_vault_entry(db_connection, jon, brock_entry) is False
        assert storage.get_vault_entry(db_connection, brock, brock_entry) is not None
        db_connection.close()


# ========== Login Attempts ==========

class Test_Login_Attempts:
    # A recorded failure is counted by email
    def test_login_failure_counted_by_email(self, tmp_path):
        db_connection = storage.db_connect(tmp_path / "test.db")
        storage.create_tables(db_connection)

        storage.record_login_attempt(db_connection, "1.1.1.1", "jon@gmail.com", 0)
        assert storage.count_recent_logins_by_email(db_connection, "jon@gmail.com", 15) == 1
        db_connection.close()

    # A recorded failure is counted by IP
    def test_login_failure_counted_by_ip(self, tmp_path):
        db_connection = storage.db_connect(tmp_path / "test.db")
        storage.create_tables(db_connection)

        storage.record_login_attempt(db_connection, "1.1.1.1", "jon@gmail.com", 0)
        assert storage.count_recent_logins_by_ip_address(db_connection, "1.1.1.1", 15) == 1
        db_connection.close()

    # Successful attempts are not failures, by email or by IP
    def test_login_success_not_counted(self, tmp_path):
        db_connection = storage.db_connect(tmp_path / "test.db")
        storage.create_tables(db_connection)

        storage.record_login_attempt(db_connection, "1.1.1.1", "jon@gmail.com", 1)
        assert storage.count_recent_logins_by_email(db_connection, "jon@gmail.com", 15) == 0
        assert storage.count_recent_logins_by_ip_address(db_connection, "1.1.1.1", 15) == 0
        db_connection.close()

    # Failures older than the window don't count
    def test_old_login_failure_not_counted(self, tmp_path):
        db_connection = storage.db_connect(tmp_path / "test.db")
        storage.create_tables(db_connection)

        db_connection.execute(
            "INSERT INTO login_attempts (ip_address, email, success, attempted_at) VALUES (?, ?, 0, datetime('now', '-20 minutes'))",
            ("1.1.1.1", "jon@gmail.com"),
        )
        db_connection.commit()
        assert storage.count_recent_logins_by_email(db_connection, "jon@gmail.com", 15) == 0
        assert storage.count_recent_logins_by_ip_address(db_connection, "1.1.1.1", 15) == 0
        db_connection.close()

    # Another email's failures don't count against this one
    def test_other_email_not_counted(self, tmp_path):
        db_connection = storage.db_connect(tmp_path / "test.db")
        storage.create_tables(db_connection)

        storage.record_login_attempt(db_connection, "1.1.1.1", "brock@gmail.com", 0)
        assert storage.count_recent_logins_by_email(db_connection, "jon@gmail.com", 15) == 0
        db_connection.close()

    # Another IP's failures don't count against this one
    def test_other_ip_not_counted(self, tmp_path):
        db_connection = storage.db_connect(tmp_path / "test.db")
        storage.create_tables(db_connection)

        storage.record_login_attempt(db_connection, "2.2.2.2", "jon@gmail.com", 0)
        assert storage.count_recent_logins_by_ip_address(db_connection, "1.1.1.1", 15) == 0
        db_connection.close()

    # Capital letters count as the same email
    def test_email_case_ignored(self, tmp_path):
        db_connection = storage.db_connect(tmp_path / "test.db")
        storage.create_tables(db_connection)

        storage.record_login_attempt(db_connection, "1.1.1.1", "JON@Gmail.com", 0)
        assert storage.count_recent_logins_by_email(db_connection, "jon@gmail.com", 15) == 1
        db_connection.close()


# ========== Register Attempts ==========

class Test_Register_Attempts:
    # A recorded register attempt is counted by IP
    def test_register_attempt_counted_by_ip(self, tmp_path):
        db_connection = storage.db_connect(tmp_path / "test.db")
        storage.create_tables(db_connection)

        storage.record_register_attempt(db_connection, "1.1.1.1")
        storage.record_register_attempt(db_connection, "1.1.1.1")
        assert storage.count_recent_registers_by_ip_address(db_connection, "1.1.1.1", 15) == 2
        db_connection.close()

    # Register attempts older than the window don't count
    def test_old_register_attempt_not_counted(self, tmp_path):
        db_connection = storage.db_connect(tmp_path / "test.db")
        storage.create_tables(db_connection)

        db_connection.execute(
            "INSERT INTO register_attempts (ip_address, attempted_at) VALUES (?, datetime('now', '-20 minutes'))",
            ("1.1.1.1",),
        )
        db_connection.commit()
        assert storage.count_recent_registers_by_ip_address(db_connection, "1.1.1.1", 15) == 0
        db_connection.close()

    # Another IP's register attempts don't count against this one
    def test_other_ip_register_not_counted(self, tmp_path):
        db_connection = storage.db_connect(tmp_path / "test.db")
        storage.create_tables(db_connection)

        storage.record_register_attempt(db_connection, "2.2.2.2")
        assert storage.count_recent_registers_by_ip_address(db_connection, "1.1.1.1", 15) == 0
        db_connection.close()