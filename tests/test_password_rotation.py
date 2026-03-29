from datetime import datetime, timezone

from src.core.crypto.authentication import AuthenticationService
from src.core.crypto.key_derivation import derive_encryption_key
from src.core.crypto.vault_crypto import encrypt_record, decrypt_record
from src.core.key_manager import KeyManager
from src.core.password_rotation import PasswordRotationService


def test_password_rotation_reencrypts_10_entries_and_new_password_opens_them(test_db):
    km = KeyManager(test_db)
    km.initialize_master_password("StrongPass123!")

    auth = AuthenticationService(km)
    old_enc_key = auth.login("StrongPass123!")
    bundle_before = km.load_bundle()

    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    original_rows = []
    with test_db.connection() as conn:
        for i in range(10):
            title = f"title_{i}"
            username = f"user_{i}"
            password = f"pass_{i}_Strong!"
            notes = f"note_{i}"
            url = f"https://example.com/{i}"
            tags = f"tag{i}"

            enc_password = encrypt_record(old_enc_key, password)
            enc_notes = encrypt_record(old_enc_key, notes)

            conn.execute(
                """
                INSERT INTO vault_entries (
                    title, username, encrypted_password, url, notes,
                    created_at, updated_at, tags
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (title, username, enc_password, url, enc_notes, now, now, tags),
            )

            original_rows.append(
                {
                    "title": title,
                    "username": username,
                    "password": password,
                    "notes": notes,
                    "url": url,
                    "tags": tags,
                }
            )
        conn.commit()

    rotation = PasswordRotationService(test_db, km)
    rotation.rotate_password("StrongPass123!", "NewStrongPass123!")

    # старый пароль больше не должен проходить
    old_auth = AuthenticationService(km)
    old_failed = False
    try:
        old_auth.login("StrongPass123!")
    except ValueError:
        old_failed = True
    assert old_failed is True

    # новый пароль должен открывать хранилище
    new_auth = AuthenticationService(km)
    new_enc_key = new_auth.login("NewStrongPass123!")
    assert isinstance(new_enc_key, bytes)
    assert len(new_enc_key) == 32

    bundle_after = km.load_bundle()
    assert bundle_after["auth_hash"] != bundle_before["auth_hash"]
    assert bundle_after["auth_salt"] != bundle_before["auth_salt"]
    assert bundle_after["enc_salt"] != bundle_before["enc_salt"]

    # дополнительно убеждаемся, что ключ действительно изменился
    rederived_new_key = derive_encryption_key(
        password="NewStrongPass123!",
        salt=bundle_after["enc_salt"],
        params=bundle_after["pbkdf2_params"],
    )
    assert rederived_new_key == new_enc_key
    assert rederived_new_key != old_enc_key

    with test_db.connection() as conn:
        rows = conn.execute(
            """
            SELECT title, username, encrypted_password, url, notes, tags
            FROM vault_entries
            ORDER BY id
            """
        ).fetchall()

    assert len(rows) == 10

    for row, expected in zip(rows, original_rows):
        assert row["title"] == expected["title"]
        assert row["username"] == expected["username"]
        assert row["url"] == expected["url"]
        assert row["tags"] == expected["tags"]

        decrypted_password = decrypt_record(new_enc_key, row["encrypted_password"])
        decrypted_notes = decrypt_record(new_enc_key, row["notes"])

        assert decrypted_password == expected["password"]
        assert decrypted_notes == expected["notes"]