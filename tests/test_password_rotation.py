import json
from datetime import datetime, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.core.crypto.authentication import AuthenticationService
from src.core.crypto.key_derivation import derive_encryption_key
from src.core.key_manager import KeyManager
from src.core.password_rotation import PasswordRotationService
from src.core.state_manager import StateManager


def _encrypt_payload(payload: dict, key: bytes) -> bytes:
    nonce = b"0" * 12
    plaintext = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def _decrypt_payload(blob: bytes, key: bytes) -> dict:
    nonce = blob[:12]
    ciphertext = blob[12:]
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return json.loads(plaintext.decode("utf-8"))


def test_password_rotation_reencrypts_10_entries_and_new_password_opens_them(test_db):
    km = KeyManager(test_db)
    km.initialize_master_password("A_StrongPass123!")

    state = StateManager()
    auth = AuthenticationService(km, state)

    old_enc_key = auth.login("A_StrongPass123!")
    assert isinstance(old_enc_key, bytes)
    assert len(old_enc_key) == 32
    assert state.session.unlocked is True

    bundle_before = km.load_bundle()
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    original_rows = []

    with test_db.connection() as conn:
        for i in range(10):
            payload = {
                "title": f"title_{i}",
                "username": f"user_{i}",
                "password": f"pass_{i}_Strong!",
                "url": f"https://example.com/{i}",
                "notes": f"note_{i}",
                "created_at": now,
                "version": 1,
            }

            encrypted_data = _encrypt_payload(payload, old_enc_key)

            conn.execute(
                """
                INSERT INTO vault_entries (
                    encrypted_data, created_at, updated_at, tags
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    encrypted_data,
                    now,
                    now,
                    f"tag{i}",
                ),
            )

            original_rows.append(
                {
                    "payload": payload,
                    "tags": f"tag{i}",
                }
            )

        conn.commit()

    rotation = PasswordRotationService(test_db, km)
    rotation.rotate_password("A_StrongPass123!", "B_StrongPass456!")

    # старый пароль больше не должен проходить
    old_state = StateManager()
    old_auth = AuthenticationService(km, old_state)

    old_failed = False
    try:
        old_auth.login("A_StrongPass123!")
    except ValueError:
        old_failed = True

    assert old_failed is True

    # новый пароль должен открывать хранилище
    new_state = StateManager()
    new_auth = AuthenticationService(km, new_state)

    new_enc_key = new_auth.login("B_StrongPass456!")
    assert isinstance(new_enc_key, bytes)
    assert len(new_enc_key) == 32
    assert new_state.session.unlocked is True

    bundle_after = km.load_bundle()

    assert bundle_after["auth_hash"] != bundle_before["auth_hash"]
    assert bundle_after["auth_salt"] != bundle_before["auth_salt"]
    assert bundle_after["enc_salt"] != bundle_before["enc_salt"]

    rederived_new_key = derive_encryption_key(
        password="B_StrongPass456!",
        salt=bundle_after["enc_salt"],
        params=bundle_after["pbkdf2_params"],
    )

    assert rederived_new_key == new_enc_key
    assert rederived_new_key != old_enc_key

    with test_db.connection() as conn:
        rows = conn.execute(
            """
            SELECT id, encrypted_data, tags
            FROM vault_entries
            ORDER BY id
            """
        ).fetchall()

    assert len(rows) == 10

    for row, expected in zip(rows, original_rows):
        decrypted_payload = _decrypt_payload(row["encrypted_data"], new_enc_key)

        assert decrypted_payload["title"] == expected["payload"]["title"]
        assert decrypted_payload["username"] == expected["payload"]["username"]
        assert decrypted_payload["password"] == expected["payload"]["password"]
        assert decrypted_payload["url"] == expected["payload"]["url"]
        assert decrypted_payload["notes"] == expected["payload"]["notes"]
        assert decrypted_payload["version"] == expected["payload"]["version"]
        assert row["tags"] == expected["tags"]