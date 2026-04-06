import json

from src.core.vault.encryption_service import VaultEncryptionService


def test_encrypt_decrypt_cycle_integrity_and_no_plaintext(test_db, unlocked_key_manager, vault_service):
    data = {
        "title": "Known Title 42",
        "username": "known.user@example.com",
        "password": "UltraStrong!Pass42",
        "url": "https://known.example.com/login",
        "notes": "Very secret notes 42",
        "category": "work",
        "tags": "alpha,beta",
    }

    created = vault_service.create_entry(data)

    with test_db.connection() as conn:
        row = conn.execute(
            """
            SELECT id, encrypted_data, created_at, updated_at, tags
            FROM vault_entries
            WHERE id = ?
            """,
            (created.id,),
        ).fetchone()

    assert row is not None
    encrypted_blob = row["encrypted_data"]
    assert isinstance(encrypted_blob, (bytes, bytearray))
    assert len(encrypted_blob) > 16

    forbidden_plaintexts = [
        data["title"],
        data["username"],
        data["password"],
        data["url"],
        data["notes"],
        data["category"],
    ]

    for value in forbidden_plaintexts:
        assert value.encode("utf-8") not in encrypted_blob

    crypto = VaultEncryptionService(unlocked_key_manager)
    decrypted_payload = crypto.decrypt_entry_payload(encrypted_blob)

    assert decrypted_payload["title"] == data["title"]
    assert decrypted_payload["username"] == data["username"]
    assert decrypted_payload["password"] == data["password"]
    assert decrypted_payload["url"] == data["url"]
    assert decrypted_payload["notes"] == data["notes"]
    assert decrypted_payload["category"] == data["category"]
    assert decrypted_payload["version"] == 1

    loaded = vault_service.get_entry(created.id)

    assert loaded is not None
    assert loaded.id == created.id
    assert loaded.title == data["title"]
    assert loaded.username == data["username"]
    assert loaded.password == data["password"]
    assert loaded.url == data["url"]
    assert loaded.notes == data["notes"]
    assert loaded.category == data["category"]
    assert loaded.tags == data["tags"]