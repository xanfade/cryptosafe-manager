import json

import pytest

from src.core.import_export.key_exchange import KeyExchangeService


def test_key_exchange_x25519_encrypts_and_decrypts_roundtrip():
    sender = KeyExchangeService(algorithm="x25519")
    recipient = KeyExchangeService(algorithm="x25519")
    payload = b"top-secret-payload"

    encrypted = sender.encrypt_for_recipient(payload, recipient.export_public_key())
    decrypted = recipient.decrypt_from_sender(encrypted, sender.export_public_key())

    assert decrypted == payload


@pytest.mark.parametrize("algorithm", ["x25519", "p256", "rsa2048"])
def test_key_exchange_wrap_unwrap_key_roundtrip(algorithm):
    sender = KeyExchangeService(algorithm="p256")
    recipient = KeyExchangeService(algorithm=algorithm)
    secret = b"k" * 32

    package = sender.wrap_key_for_recipient(secret, recipient.export_public_key())
    unwrapped = recipient.unwrap_key_from_sender(package)

    assert unwrapped == secret


def test_key_exchange_database_contacts_and_rotation(test_db):
    service = KeyExchangeService.from_database(test_db, algorithm="p256")
    bundle = service.export_public_bundle(owner="alice")

    service.store_contact("alice", bundle, verified=False)
    contacts = service.list_contacts()
    assert "alice" in contacts
    assert service.verify_contact_fingerprint("alice", bundle["fingerprint"]) is True

    service.revoke_contact("alice")
    assert service.list_contacts()["alice"]["revoked"] is True

    rotated = service.rotate_identity("rsa2048")
    assert rotated["algorithm"] == "rsa2048"


def test_key_exchange_from_database_reuses_persisted_identity(test_db):
    first = KeyExchangeService.from_database(test_db, algorithm="p256")
    saved = json.loads(test_db.get_setting(KeyExchangeService.IDENTITY_SETTING, ""))
    second = KeyExchangeService.from_database(test_db, algorithm="x25519")

    assert saved["algorithm"] == "p256"
    assert second.algorithm == "p256"
    assert second.export_public_key() == first.export_public_key()


def test_key_exchange_sign_and_verify_for_p256_and_rsa():
    payload = b"verify me"

    p256 = KeyExchangeService(algorithm="p256")
    p256_sig = p256.sign(payload)
    assert KeyExchangeService.verify_signature("p256", p256.export_public_key(), payload, p256_sig) is True

    rsa = KeyExchangeService(algorithm="rsa2048")
    rsa_sig = rsa.sign(payload)
    assert KeyExchangeService.verify_signature("rsa2048", rsa.export_public_key(), payload, rsa_sig) is True


def test_key_exchange_sign_rejects_unsupported_algorithm():
    service = KeyExchangeService(algorithm="x25519")

    with pytest.raises(ValueError):
        service.sign(b"no-sign")
