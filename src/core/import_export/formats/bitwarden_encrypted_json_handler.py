from __future__ import annotations

import base64
import json
import os
import uuid
from typing import Any

from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class BitwardenEncryptedJsonFormatHandler:
    KDF_TYPE_PBKDF2 = 0
    DEFAULT_PBKDF2_ITERATIONS = 600_000

    def serialize(
        self,
        entries: list[dict[str, Any]],
        password: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> bytes:
        if not password:
            raise PermissionError("export password is required")
        plaintext_export = self._build_plaintext_export(entries)
        plaintext_bytes = json.dumps(plaintext_export, ensure_ascii=False, indent=2).encode("utf-8")

        salt_bytes = os.urandom(16)
        salt_b64 = base64.b64encode(salt_bytes).decode("ascii")
        pin_key = self._derive_kdf_material(password, salt_b64)
        enc_key, mac_key = self._stretch_key(pin_key)

        validation = self._encrypt_string(str(uuid.uuid4()), enc_key, mac_key)
        data = self._encrypt_bytes(plaintext_bytes, enc_key, mac_key)
        package = {
            "encrypted": True,
            "passwordProtected": True,
            "salt": salt_b64,
            "kdfType": self.KDF_TYPE_PBKDF2,
            "kdfIterations": self.DEFAULT_PBKDF2_ITERATIONS,
            "kdfMemory": None,
            "kdfParallelism": None,
            "encKeyValidation_DO_NOT_EDIT": validation,
            "data": data,
        }
        return json.dumps(package, ensure_ascii=False, indent=2).encode("utf-8")

    def deserialize(self, payload: bytes, password: str | None = None) -> list[dict[str, Any]]:
        if not password:
            raise PermissionError("import password is required")
        package = json.loads(payload.decode("utf-8"))
        pin_key = self._derive_kdf_material(
            password,
            str(package.get("salt", "")),
            int(package.get("kdfIterations", self.DEFAULT_PBKDF2_ITERATIONS)),
        )
        enc_key, mac_key = self._stretch_key(pin_key)
        plaintext = self._decrypt_bytes(str(package.get("data", "")), enc_key, mac_key)
        plain_export = json.loads(plaintext.decode("utf-8"))
        return self._parse_plaintext_export(plain_export)

    def _build_plaintext_export(self, entries: list[dict[str, Any]]) -> dict[str, Any]:
        folder_map: dict[str, str] = {}
        folders: list[dict[str, Any]] = []
        items: list[dict[str, Any]] = []

        for entry in entries:
            category = str(entry.get("category", "") or "").strip()
            folder_id: str | None = None
            if category:
                folder_id = folder_map.get(category)
                if folder_id is None:
                    folder_id = str(uuid.uuid4())
                    folder_map[category] = folder_id
                    folders.append({"id": folder_id, "name": category})

            custom_fields = self._build_custom_fields(entry)
            item = {
                "name": str(entry.get("title", "") or ""),
                "type": 1,
                "notes": self._optional_text(entry.get("notes")),
                "login": {
                    "uris": (
                        [{"uri": str(entry.get("url", "")), "match": None}]
                        if entry.get("url")
                        else []
                    ),
                    "username": self._optional_text(entry.get("username")),
                    "password": self._optional_text(entry.get("password")),
                    "totp": None,
                },
                "reprompt": 0,
                "favorite": False,
            }
            item["id"] = str(uuid.uuid4())
            item["organizationId"] = None
            item["folderId"] = folder_id
            item["collectionIds"] = None
            if custom_fields:
                item["fields"] = custom_fields
            items.append(item)

        return {
            "encrypted": False,
            "folders": folders,
            "items": items,
        }

    @staticmethod
    def _build_custom_fields(entry: dict[str, Any]) -> list[dict[str, Any]]:
        fields: list[dict[str, Any]] = []
        tags = str(entry.get("tags", "") or "").strip()
        if tags:
            fields.append(
                {
                    "name": "tags",
                    "value": tags,
                    "type": 0,
                    "linkedId": None,
                }
            )
        return fields

    def _parse_plaintext_export(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        folders = payload.get("folders", []) or []
        folder_names = {
            str(folder.get("id")): str(folder.get("name") or "")
            for folder in folders
            if isinstance(folder, dict) and folder.get("id")
        }
        entries: list[dict[str, Any]] = []
        for item in payload.get("items", []) or []:
            if not isinstance(item, dict):
                continue
            login = item.get("login", {}) or {}
            uris = login.get("uris", []) or []
            url = uris[0].get("uri", "") if uris and isinstance(uris[0], dict) else ""
            fields = item.get("fields", []) or []
            tags = ",".join(
                str(field.get("name", "")).strip()
                for field in fields
                if isinstance(field, dict) and field.get("name")
            )
            entries.append(
                {
                    "title": item.get("name", ""),
                    "username": login.get("username", ""),
                    "password": login.get("password", ""),
                    "url": url,
                    "notes": item.get("notes", ""),
                    "category": folder_names.get(str(item.get("folderId")), ""),
                    "tags": tags,
                }
            )
        return entries

    def _derive_kdf_material(
        self,
        password: str,
        salt_b64: str,
        iterations: int | None = None,
    ) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_b64.encode("ascii"),
            iterations=max(self.DEFAULT_PBKDF2_ITERATIONS, int(iterations or self.DEFAULT_PBKDF2_ITERATIONS)),
        )
        return kdf.derive(password.encode("utf-8"))

    @staticmethod
    def _stretch_key(pin_key: bytes) -> tuple[bytes, bytes]:
        enc_key = HKDFExpand(
            algorithm=hashes.SHA256(),
            length=32,
            info=b"enc",
        ).derive(pin_key)
        mac_key = HKDFExpand(
            algorithm=hashes.SHA256(),
            length=32,
            info=b"mac",
        ).derive(pin_key)
        return enc_key, mac_key

    def _encrypt_string(self, plaintext: str, enc_key: bytes, mac_key: bytes) -> str:
        return self._encrypt_bytes(plaintext.encode("utf-8"), enc_key, mac_key)

    @staticmethod
    def _encrypt_bytes(plaintext: bytes, enc_key: bytes, mac_key: bytes) -> str:
        iv = os.urandom(16)
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded = padder.update(plaintext) + padder.finalize()
        cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()

        signer = hmac.HMAC(mac_key, hashes.SHA256())
        signer.update(iv + ciphertext)
        mac = signer.finalize()

        return "2.{iv}|{data}|{mac}".format(
            iv=base64.b64encode(iv).decode("ascii"),
            data=base64.b64encode(ciphertext).decode("ascii"),
            mac=base64.b64encode(mac).decode("ascii"),
        )

    @staticmethod
    def _decrypt_bytes(encrypted: str, enc_key: bytes, mac_key: bytes) -> bytes:
        prefix, encoded_parts = encrypted.split(".", 1)
        if prefix != "2":
            raise ValueError("unsupported Bitwarden encrypted string type")
        iv_b64, data_b64, mac_b64 = encoded_parts.split("|", 2)
        iv = base64.b64decode(iv_b64)
        ciphertext = base64.b64decode(data_b64)
        expected_mac = base64.b64decode(mac_b64)

        signer = hmac.HMAC(mac_key, hashes.SHA256())
        signer.update(iv + ciphertext)
        signer.verify(expected_mac)

        cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        return unpadder.update(padded) + unpadder.finalize()

    @staticmethod
    def _optional_text(value: Any) -> str | None:
        if value is None:
            return None
        text = str(value)
        return text if text else None
