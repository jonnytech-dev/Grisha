from core import auth, crypto, storage
import pytest
from cryptography.exceptions import InvalidTag
import os


def setup_db(tmp_path):
    # Fresh DB with tables for each test
    db_connection = storage.db_connect(tmp_path / "test.db")
    storage.create_tables(db_connection)
    return db_connection


# ========== Register ==========

class Test_Register:
    # register returns user_id if creation is successful
    def test_register_returns_user_id(self, tmp_path):
        db_connection = setup_db(tmp_path)
        register_user = auth.register(db_connection, "jon", "jon@gmail.com", "correct111-horse-battery")
        assert isinstance(register_user, str)

        db_connection.close()

    # Password must be atleast 12 characters, this test 11 only
    def test_register_with_too_short_password(self, tmp_path):
        db_connection = setup_db(tmp_path)
        
        with pytest.raises(ValueError):
            auth.register(db_connection, "jon", "johnnymailman@gmail.com", "12345678911")

        db_connection.close()

    # Password must be atleast 12 characters, this test 12 exactly
    def test_register_with_minimal_password(self, tmp_path):
        db_connection = setup_db(tmp_path)
        
        assert isinstance(auth.register(db_connection, "jon", "johnnymailman@gmail.com", "123456789112"), str)

        db_connection.close()

    # Password must be at most 256 characters, this test 256 exactly
    def test_register_with_maximum_password(self, tmp_path):
        db_connection = setup_db(tmp_path)
        password = "a" * 250 + "123!@#" 
        
        
        assert isinstance(auth.register(db_connection, "jon", "johnnymailman@gmail.com", password), str)

        db_connection.close()

    # Password must be at most 256 characters, this test 257
    def test_register_with_too_long_password(self, tmp_path):
        db_connection = setup_db(tmp_path)
        password = "a" * 250 + "123!@#7" 
        
        with pytest.raises(ValueError):
            auth.register(db_connection, "jon", "johnnymailman@gmail.com", password)

        db_connection.close()

    # # Password must have atleast 3 numbers or 3 special characters
    # def test_register_password_not_strong(self, tmp_path):
    #     db_connection = setup_db(tmp_path)
        
    #     with pytest.raises(ValueError):
    #         auth.register(db_connection, "jonnnnnn", "johnnygfdgdfg@gmail.com", "Panda-Turtle-Dove")

    #     db_connection.close()

    # The stored hash must verify with the real password, and must not be the password
    def test_register_stores_real_password_hash(self, tmp_path):
        db_connection = setup_db(tmp_path)
        auth.register(db_connection, "jon", "jon@gmail.com", "c0rrect1horseb@ttery")

        user = storage.find_email(db_connection, "jon@gmail.com")
        assert user["password_hash"] != "c0rrect1horseb@ttery"
        assert crypto.verify_password(user["password_hash"], "c0rrect1horseb@ttery")
        db_connection.close()

    # The full chain: password + stored salt rebuilds the KEK, which unwraps the stored DEK
    def test_register_dek_unwraps_with_password(self, tmp_path):
        db_connection = setup_db(tmp_path)
        user_id = auth.register(db_connection, "jon", "jon@gmail.com", "c0rrect1horseb@ttery")

        user = storage.find_email(db_connection, "jon@gmail.com")
        kek = crypto.derive_kek("c0rrect1horseb@ttery", user["kek_salt"])
        aad = f"user:{user_id}:dek".encode()
        dek = crypto.decrypt(kek, user["encrypted_dek_nonce"], user["encrypted_dek"], aad)
        assert len(dek) == 32
        db_connection.close()

    # New accounts are never admins
    def test_register_role_is_user(self, tmp_path):
        db_connection = setup_db(tmp_path)
        auth.register(db_connection, "jon", "jon@gmail.com", "c0rrect1horseb@ttery")
        assert storage.find_email(db_connection, "jon@gmail.com")["role"] == "user"
        db_connection.close()

    # A short password is rejected before anything is saved
    def test_register_short_password_fails(self, tmp_path):
        db_connection = setup_db(tmp_path)
        with pytest.raises(ValueError):
            auth.register(db_connection, "jon", "jon@gmail.com", "short")
        assert storage.find_email(db_connection, "jon@gmail.com") is None
        db_connection.close()

    # A duplicate email raises the app's own error, not a database error
    def test_register_duplicate_email_fails(self, tmp_path):
        db_connection = setup_db(tmp_path)
        auth.register(db_connection, "jon", "jon@gmail.com", "c0rrect1horseb@ttery")
        with pytest.raises(auth.UserExistsError):
            auth.register(db_connection, "gavin", "jon@gmail.com", "correct111-horse-battery")
        db_connection.close()

    # A duplicate username raises the same error
    def test_register_duplicate_username_fails(self, tmp_path):
        db_connection = setup_db(tmp_path)
        auth.register(db_connection, "jon", "jon@gmail.com", "c0rrect1horseb@ttery")
        with pytest.raises(auth.UserExistsError):
            auth.register(db_connection, "jon", "gavin@gmail.com", "correct111-horse-battery")
        db_connection.close()

# ========== Login ==========

PASSWORD = "c0rrect1horseb@ttery"

class Test_Login:
    # Correct email and password returns a Session for that user
    def test_login_success(self, tmp_path):
        db_connection = setup_db(tmp_path)
        user_id = auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)

        session = auth.login(db_connection, "jon@gmail.com", PASSWORD)
        assert session.user_id == user_id
        assert session.role == "user"
        assert len(session.dek) == 32
        db_connection.close()

    # Two logins must give back the SAME DEK, or old entries could never be read
    def test_login_returns_same_dek_each_time(self, tmp_path):
        db_connection = setup_db(tmp_path)
        auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)

        first = auth.login(db_connection, "jon@gmail.com", PASSWORD)
        second = auth.login(db_connection, "jon@gmail.com", PASSWORD)
        assert first.dek == second.dek
        db_connection.close()

    # Data locked with the DEK from one login opens with the DEK from the next login
    def test_dek_from_login_decrypts_saved_data(self, tmp_path):
        db_connection = setup_db(tmp_path)
        auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)

        session = auth.login(db_connection, "jon@gmail.com", PASSWORD)
        nonce, ciphertext = crypto.encrypt(session.dek, b"gmail-password", b"test")

        session_again = auth.login(db_connection, "jon@gmail.com", PASSWORD)
        assert crypto.decrypt(session_again.dek, nonce, ciphertext, b"test") == b"gmail-password"
        db_connection.close()

    # Login works no matter how the email is capitalized
    def test_login_email_any_case(self, tmp_path):
        db_connection = setup_db(tmp_path)
        user_id = auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)

        session = auth.login(db_connection, "JON@Gmail.COM", PASSWORD)
        assert session.user_id == user_id
        db_connection.close()

    # Wrong password fails
    def test_login_wrong_password(self, tmp_path):
        db_connection = setup_db(tmp_path)
        auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)

        with pytest.raises(auth.InvalidCredentialsError):
            auth.login(db_connection, "jon@gmail.com", "wr0ng!password")
        db_connection.close()

    # Unknown email fails with the same error
    def test_login_unknown_email(self, tmp_path):
        db_connection = setup_db(tmp_path)

        with pytest.raises(auth.InvalidCredentialsError):
            auth.login(db_connection, "nobody@gmail.com", PASSWORD)
        db_connection.close()

    # Wrong email and wrong password must give the exact same message
    def test_login_errors_look_identical(self, tmp_path):
        db_connection = setup_db(tmp_path)
        auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)

        with pytest.raises(auth.InvalidCredentialsError) as wrong_password:
            auth.login(db_connection, "jon@gmail.com", "wr0ng!password")
        with pytest.raises(auth.InvalidCredentialsError) as unknown_email:
            auth.login(db_connection, "nobody@gmail.com", PASSWORD)

        assert str(wrong_password.value) == str(unknown_email.value)
        db_connection.close()

    # A tampered encrypted DEK must fail loudly, not look like a wrong password
    def test_login_tampered_dek_fails_loudly(self, tmp_path):
        db_connection = setup_db(tmp_path)
        auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)
        db_connection.execute("UPDATE users SET encrypted_dek = ?", (os.urandom(48),))
        db_connection.commit()

        with pytest.raises(InvalidTag):
            auth.login(db_connection, "jon@gmail.com", PASSWORD)
        db_connection.close()


# ========== Login Lockout ==========

class Test_Login_Lockout:
    # Too many wrong passwords lock the email, even if the next one is correct
    def test_email_locks_after_max_failures(self, tmp_path):
        db_connection = setup_db(tmp_path)
        auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)

        for _ in range(auth.MAX_FAILED_LOGIN_ATTEMPTS):
            with pytest.raises(auth.InvalidCredentialsError):
                auth.login(db_connection, "jon@gmail.com", "wr0ng!password")

        with pytest.raises(auth.AccountLockedError):
            auth.login(db_connection, "jon@gmail.com", PASSWORD)
        db_connection.close()

    # One under the limit still lets the correct password in
    def test_login_works_under_limit(self, tmp_path):
        db_connection = setup_db(tmp_path)
        user_id = auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)

        for _ in range(auth.MAX_FAILED_LOGIN_ATTEMPTS - 1):
            with pytest.raises(auth.InvalidCredentialsError):
                auth.login(db_connection, "jon@gmail.com", "wr0ng!password")

        assert auth.login(db_connection, "jon@gmail.com", PASSWORD).user_id == user_id
        db_connection.close()

    # Successful logins must never count toward the lockout
    def test_successful_logins_never_lock(self, tmp_path):
        db_connection = setup_db(tmp_path)
        user_id = auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)

        for _ in range(auth.MAX_FAILED_LOGIN_ATTEMPTS + 1):
            assert auth.login(db_connection, "jon@gmail.com", PASSWORD).user_id == user_id
        db_connection.close()

    # Unknown emails lock the same way, so lockout can't reveal who has an account
    def test_unknown_email_also_locks(self, tmp_path):
        db_connection = setup_db(tmp_path)

        for _ in range(auth.MAX_FAILED_LOGIN_ATTEMPTS):
            with pytest.raises(auth.InvalidCredentialsError):
                auth.login(db_connection, "nobody@gmail.com", PASSWORD)

        with pytest.raises(auth.AccountLockedError):
            auth.login(db_connection, "nobody@gmail.com", PASSWORD)
        db_connection.close()

    # Failures older than the window no longer lock the account
    def test_lockout_expires(self, tmp_path):
        db_connection = setup_db(tmp_path)
        user_id = auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)

        for _ in range(auth.MAX_FAILED_LOGIN_ATTEMPTS):
            db_connection.execute(
                "INSERT INTO login_attempts (ip_address, email, success, attempted_at) VALUES (?, ?, 0, datetime('now', '-20 minutes'))",
                (None, "jon@gmail.com"),
            )
        db_connection.commit()

        assert auth.login(db_connection, "jon@gmail.com", PASSWORD).user_id == user_id
        db_connection.close()

    # One IP trying many different emails gets locked out (password spraying)
    def test_ip_locks_after_max_failures(self, tmp_path):
        db_connection = setup_db(tmp_path)
        auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)

        for number in range(auth.MAX_FAILED_LOGIN_ATTEMPTS):
            with pytest.raises(auth.InvalidCredentialsError):
                auth.login(db_connection, f"victim{number}@gmail.com", PASSWORD, ip_address="6.6.6.6")

        # Even a real user with the correct password is blocked from that IP
        with pytest.raises(auth.AccountLockedError):
            auth.login(db_connection, "jon@gmail.com", PASSWORD, ip_address="6.6.6.6")
        db_connection.close()

    # A locked IP does not affect other IPs
    def test_ip_lock_does_not_affect_other_ips(self, tmp_path):
        db_connection = setup_db(tmp_path)
        user_id = auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)

        for number in range(auth.MAX_FAILED_LOGIN_ATTEMPTS):
            with pytest.raises(auth.InvalidCredentialsError):
                auth.login(db_connection, f"victim{number}@gmail.com", PASSWORD, ip_address="6.6.6.6")

        assert auth.login(db_connection, "jon@gmail.com", PASSWORD, ip_address="1.1.1.1").user_id == user_id
        db_connection.close()


# ========== Register Limit ==========

class Test_Register_Limit:
    # Too many registers from one IP are blocked
    def test_register_limit_by_ip(self, tmp_path):
        db_connection = setup_db(tmp_path)

        for number in range(auth.MAX_FAILED_REGISTER_ATTEMPTS):
            auth.register(db_connection, f"user{number}", f"user{number}@gmail.com", PASSWORD, ip_address="6.6.6.6")

        with pytest.raises(auth.AccountLockedError):
            auth.register(db_connection, "one_more", "one_more@gmail.com", PASSWORD, ip_address="6.6.6.6")
        db_connection.close()

    # Duplicate-account attempts still count toward the limit
    def test_duplicate_registers_count(self, tmp_path):
        db_connection = setup_db(tmp_path)
        auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD, ip_address="6.6.6.6")

        for _ in range(auth.MAX_FAILED_REGISTER_ATTEMPTS - 1):
            with pytest.raises(auth.UserExistsError):
                auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD, ip_address="6.6.6.6")

        with pytest.raises(auth.AccountLockedError):
            auth.register(db_connection, "new", "new@gmail.com", PASSWORD, ip_address="6.6.6.6")
        db_connection.close()

    # Weak passwords are not logged as register attempts
    def test_weak_password_not_counted(self, tmp_path):
        db_connection = setup_db(tmp_path)

        for _ in range(auth.MAX_FAILED_REGISTER_ATTEMPTS):
            with pytest.raises(ValueError):
                auth.register(db_connection, "jon", "jon@gmail.com", "short", ip_address="6.6.6.6")

        assert isinstance(auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD, ip_address="6.6.6.6"), str)
        db_connection.close()

    # A blocked IP does not affect other IPs
    def test_register_limit_does_not_affect_other_ips(self, tmp_path):
        db_connection = setup_db(tmp_path)

        for number in range(auth.MAX_FAILED_REGISTER_ATTEMPTS):
            auth.register(db_connection, f"user{number}", f"user{number}@gmail.com", PASSWORD, ip_address="6.6.6.6")

        assert isinstance(auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD, ip_address="1.1.1.1"), str)
        db_connection.close()