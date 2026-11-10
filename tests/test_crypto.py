from core import crypto
import os
import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


# ========== Password Hashing ==========

class Test_Password_Hashing:
    def test_correct_password_verifies(self):
        # The hash verification should return as true
        h = crypto.hash_password("hunter2")
        assert crypto.verify_password(h, "hunter2")

    def test_incorrect_password_verifies(self):
        # The hash verification should return as false
        h = crypto.hash_password("hunter2")
        assert crypto.verify_password(h, "tomato2") is False

    def test_same_password_gives_different_hashes(self):
        # Each hash gets a new random salt, so the same password never makes the same hash twice.
        # This hides users who share a password and blocks precomputed (rainbow table) attacks.
        assert crypto.hash_password("hunter2") != crypto.hash_password("hunter2")

    def test_password_is_not_plaintext(self):
        # The plaintext password must never show up inside the stored hash.
        # Safety net in case hash_password is ever changed to return the password by mistake.
        assert "hunter2" not in crypto.hash_password("hunter2")


# ========== Salt / Key Encryption Key (KEK) ==========

class Test_Key_Derivation:
    def test_new_salt_is_16_random_bytes(self):
        # A salt must be bytes, 16 bytes long, and different every time it is created.
        a = crypto.new_salt()
        b = crypto.new_salt()
        assert isinstance(a, bytes)
        assert len(a) == 16
        assert a != b

    def test_kek_is_32_bytes(self):
        # The KEK must be exactly 32 bytes, since AES-256 needs a 32 byte key.
        key = crypto.derive_kek("hunter2", crypto.new_salt())
        assert isinstance(key, bytes)
        assert len(key) == 32

    def test_same_password_same_salt_same_key(self):
        # The KEK must come out the same every login, or the DEK could never be decrypted again.
        # Same password + same stored salt = same KEK.
        salt = crypto.new_salt()
        assert crypto.derive_kek("hunter2", salt) == crypto.derive_kek("hunter2", salt)

    def test_same_password_different_salt_different_key(self):
        # Two users with the same password get different KEKs, because each user has their own salt.
        assert crypto.derive_kek("hunter2", crypto.new_salt()) != crypto.derive_kek("hunter2", crypto.new_salt())

    def test_different_password_same_salt_different_key(self):
        # A wrong password must never rebuild the right KEK, even with the correct salt.
        salt = crypto.new_salt()
        assert crypto.derive_kek("hunter2", salt) != crypto.derive_kek("hunter3", salt)


# ========== Data Encryption Key (DEK) ==========

class Test_Data_Encryption_Key:
    def test_create_new_dek(self):
        # create a new dek

        dek = crypto.new_dek()
        assert isinstance(dek, bytes)
        assert len(dek) == 32

    def test_unique_dek(self):
        # new_dek must create a unique dek every run

        dek = crypto.new_dek()
        dek2 = crypto.new_dek()
        assert dek != dek2 


# ========== Encryption / Decryption ==========

class Test_Encryption_Decryption:
    def test_encrypt_unique_nonce(self):
        # encrypt() must create a unique nonce every run
        # The key, data, and aad stay the same on purpose. The only thing that should change is the nonce.
        # Reusing a nonce with the same key breaks AES-GCM's security.

        # Encrypt
        salt = crypto.new_salt()
        kek = crypto.derive_kek("hunter2", salt)
        dek = crypto.new_dek()
        aad = os.urandom(8)
        ciphertext = crypto.encrypt(kek, dek, aad)
        nonce, encrypted_data = ciphertext   # unpack data from the tuple

        ciphertext2 = crypto.encrypt(kek, dek, aad)
        nonce2, encrypted_data2 = ciphertext2   # unpack data from the tuple

        assert nonce != nonce2
        

    def test_encrypt_unencrypted_data_SUCCESS(self):
        # encrypt() must return a tuple of 2 items: the nonce and the encrypted data, both as bytes.
        salt = crypto.new_salt()
        kek = crypto.derive_kek("hunter2", salt)
        dek = crypto.new_dek()
        aad = os.urandom(8)
        ciphertext = crypto.encrypt(kek, dek, aad)
        nonce, encrypted_data = ciphertext   # unpack data from the tuple

        assert isinstance(ciphertext, tuple)
        assert len(ciphertext) == 2
        assert isinstance(nonce, bytes) 
        assert isinstance(encrypted_data, bytes)

    def test_decrypt_encrypted_data_SUCCESS(self):
        # Round trip: data encrypted with a key, nonce, and aad must decrypt back to the exact same data.
        # Encrypt the data
        salt = crypto.new_salt()
        kek = crypto.derive_kek("hunter2", salt)
        unencrypted_data = b'AmazonPassword=Meow2'
        aad = os.urandom(8)
        ciphertext = crypto.encrypt(kek, unencrypted_data, aad)  # returns nonce, encrypted_data from encrypt function
        nonce, encrypted_data = ciphertext   # unpack ciphers from the tuple

        # Decrypt the data
        decrypted_data = crypto.decrypt(kek, nonce, encrypted_data, aad)
        assert isinstance(decrypted_data, bytes)
        assert unencrypted_data == decrypted_data

    def test_plaintext_is_not_in_encrypted_cipher(self):
        # The readable data must never show up inside the encrypted data.
        # Proves the data is actually hidden, not just stored as is.
        # Encrypt the data
        salt = crypto.new_salt()
        kek = crypto.derive_kek("hunter2", salt)
        unencrypted_data = b'AmazonPassword=Meow2'
        aad = os.urandom(8)
        ciphertext = crypto.encrypt(kek, unencrypted_data, aad)  # returns nonce, encrypted_data from encrypt function
        nonce, encrypted_data = ciphertext   # unpack ciphers from the tuple

        assert unencrypted_data not in encrypted_data

    def test_next_login_decrypts_data(self):
        # Each login by the user decrypts the data the same
        # Tests the full chain: KEK unlocks the DEK, then the DEK unlocks the vault password.
        # The KEK is rebuilt from the password each login, the same way the real app will do it.

        # Encrypt the DEK with the KEK
        salt = crypto.new_salt()
        kek = crypto.derive_kek("hunter2", salt)
        dek = crypto.new_dek()
        aad = os.urandom(8)
        ciphertext = crypto.encrypt(kek, dek, aad)  
        dek_nonce, encrypted_dek = ciphertext

        # Decrypt the DEK with the KEK
        kek_relogin = crypto.derive_kek("hunter2", salt)
        decrypted_dek = crypto.decrypt(kek_relogin, dek_nonce, encrypted_dek, aad)
        assert decrypted_dek == dek

        # Use the decrypted DEK to encrypt a password that would be stored in a vault
        plaintext_password = b'SneakyPanda!22'
        password_cipher = crypto.encrypt(decrypted_dek, plaintext_password, aad)
        password_nonce, encrypted_password = password_cipher

        # Relogin and decrypt the encrypted DEK, then decrypt encrypted password
        kek_relogin_again = crypto.derive_kek("hunter2", salt)
        decrypted_dek = crypto.decrypt(kek_relogin_again, dek_nonce, encrypted_dek, aad)
        decrypted_password = crypto.decrypt(decrypted_dek, password_nonce, encrypted_password, aad)

        assert decrypted_password == plaintext_password
        

    def test_decrypt_encrypted_data_wrong_aad(self):
        # Decrypting with a different aad must fail with InvalidTag.
        # This stops an attacker from moving one user's encrypted data into another user's row.
        # Encrypt the data
        salt = crypto.new_salt()
        kek = crypto.derive_kek("hunter2", salt)
        dek = crypto.new_dek()
        aad = os.urandom(8)
        aad2 = os.urandom(8)
        ciphertext = crypto.encrypt(kek, dek, aad)  # returns nonce, encrypted_data from encrypt function
        nonce, encrypted_data = ciphertext   # unpack ciphers from the tuple

        # Decrypt the data
        with pytest.raises(InvalidTag):
            decrypted_data = crypto.decrypt(kek, nonce, encrypted_data, aad2)

    def test_decrypt_encrypted_data_wrong_key(self):
        # Simulates logging in with the wrong master password.
        # The wrong password builds the wrong KEK, so decryption must fail with InvalidTag.
        # Encrypt the data
        salt = crypto.new_salt()
        kek = crypto.derive_kek("hunter2", salt)
        kek2 = crypto.derive_kek("hunter40", salt)
        dek = crypto.new_dek()
        aad = os.urandom(8)
        ciphertext = crypto.encrypt(kek, dek, aad)  # returns nonce, encrypted_data from encrypt function
        nonce, encrypted_data = ciphertext   # unpack ciphers from the tuple

        # Decrypt the data
        with pytest.raises(InvalidTag):
            decrypted_data = crypto.decrypt(kek2, nonce, encrypted_data, aad)

    def test_decrypt_encrypted_tampered_data(self):
        # If even one bit of the encrypted data is changed, decryption must fail with InvalidTag.
        # The tag acts like a seal. Any change to the data breaks it.
        # Encrypt the data
        salt = crypto.new_salt()
        kek = crypto.derive_kek("hunter2", salt)
        dek = crypto.new_dek()
        dek2 = crypto.new_dek()
        aad = os.urandom(8)
        ciphertext = crypto.encrypt(kek, dek, aad) 
        nonce, encrypted_data = ciphertext  

        # Flips the lowest bit of the first byte, then adds the rest of the data back unchanged.
        tampered_data = bytes([encrypted_data[0] ^ 1]) + encrypted_data[1:]

        assert isinstance(ciphertext, tuple)
        assert len(ciphertext) == 2
        assert isinstance(nonce, bytes) 
        assert isinstance(encrypted_data, bytes)

        # Decrypt the data
        with pytest.raises(InvalidTag):
            decrypted_data = crypto.decrypt(kek, nonce, tampered_data, aad)

# ========== Key Pairs ==========

class Test_Key_Pairs:
    # Both keys come back as 32 bytes
    def test_key_pair_is_32_bytes_each(self):
        private_key, public_key = crypto.new_key_pair()
        assert isinstance(private_key, bytes)
        assert isinstance(public_key, bytes)
        assert len(private_key) == 32
        assert len(public_key) == 32

    # Every key pair is new and random
    def test_key_pairs_are_unique(self):
        private_a, public_a = crypto.new_key_pair()
        private_b, public_b = crypto.new_key_pair()
        assert private_a != private_b
        assert public_a != public_b

    # The public key really belongs to the private key
    def test_public_key_matches_private_key(self):
        private_key, public_key = crypto.new_key_pair()
        rebuilt = X25519PrivateKey.from_private_bytes(private_key).public_key().public_bytes_raw()
        assert rebuilt == public_key

    # The two halves are different
    def test_public_key_is_not_private_key(self):
        private_key, public_key = crypto.new_key_pair()
        assert private_key != public_key


# ========== Public Key Wrapping ==========

class Test_Public_Key_Wrapping:
    # Wrapped with Brock's public key, opened with Brock's private key
    def test_wrap_unwrap_round_trip(self):
        brock_private, brock_public = crypto.new_key_pair()
        vault_key = crypto.new_dek()

        wrapped = crypto.wrap_for_public_key(brock_public, vault_key, b"vault:v1")
        assert crypto.unwrap_with_private_key(brock_private, wrapped, b"vault:v1") == vault_key

    # Someone else's private key can't open it
    def test_wrong_private_key_fails(self):
        brock_private, brock_public = crypto.new_key_pair()
        eve_private, eve_public = crypto.new_key_pair()

        wrapped = crypto.wrap_for_public_key(brock_public, crypto.new_dek(), b"vault:v1")
        with pytest.raises(InvalidTag):
            crypto.unwrap_with_private_key(eve_private, wrapped, b"vault:v1")

    # The wrong label fails, same as AES-GCM
    def test_wrong_aad_fails(self):
        brock_private, brock_public = crypto.new_key_pair()

        wrapped = crypto.wrap_for_public_key(brock_public, crypto.new_dek(), b"vault:v1")
        with pytest.raises(InvalidTag):
            crypto.unwrap_with_private_key(brock_private, wrapped, b"vault:v2")

    # One flipped bit is caught
    def test_tampered_blob_fails(self):
        brock_private, brock_public = crypto.new_key_pair()

        wrapped = crypto.wrap_for_public_key(brock_public, crypto.new_dek(), b"vault:v1")
        tampered = wrapped[:-1] + bytes([wrapped[-1] ^ 1])
        with pytest.raises(InvalidTag):
            crypto.unwrap_with_private_key(brock_private, tampered, b"vault:v1")

    # Wrapping the same key twice gives different blobs (new throwaway pair each time)
    def test_wrapping_twice_differs(self):
        brock_private, brock_public = crypto.new_key_pair()
        vault_key = crypto.new_dek()

        first = crypto.wrap_for_public_key(brock_public, vault_key, b"vault:v1")
        second = crypto.wrap_for_public_key(brock_public, vault_key, b"vault:v1")
        assert first != second

    # The wrapped key never appears in the blob
    def test_wrapped_data_is_hidden(self):
        brock_private, brock_public = crypto.new_key_pair()
        vault_key = crypto.new_dek()

        wrapped = crypto.wrap_for_public_key(brock_public, vault_key, b"vault:v1")
        assert vault_key not in wrapped

    # Blob is temp_public (32) + nonce (12) + data + tag (16)
    def test_blob_length(self):
        brock_private, brock_public = crypto.new_key_pair()
        vault_key = crypto.new_dek()

        wrapped = crypto.wrap_for_public_key(brock_public, vault_key, b"vault:v1")
        assert len(wrapped) == 32 + 12 + len(vault_key) + 16

class test_example:
    def test_example():
        a = "a"